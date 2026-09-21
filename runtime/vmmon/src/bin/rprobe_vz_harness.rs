#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("silo-rprobe-vz-harness requires macOS ARM64");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
#[path = "rprobe/worker.rs"]
mod krun_worker;

#[cfg(target_os = "macos")]
#[path = "../rosetta/mod.rs"]
mod rosetta;

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::c_void;
    use std::fs;
    use std::future::Future;
    use std::io::{self, Read};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant as StdInstant};

    use crate::krun_worker::Worker;
    use clap::Parser;
    use eyre::{eyre, Context, Result};
    use krun::RosettaLaunchConfig;
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use rprobe::exerciser::{
        Decoder as ExerciserDecoder, CHECK_TRANSLATED_WORKLOAD, FILESYSTEM_CHECKS,
    };
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
    const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
    const HELPER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_TRANSLATOR_SIZE: usize = 128 * 1024 * 1024;
    const HELPER_DIAGNOSTIC_LIMIT: usize = 4096;
    const DEFAULT_HOST_ROOT: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux";

    #[derive(Debug, Parser)]
    struct Args {
        #[arg(long, value_name = "PATH")]
        kernel: PathBuf,
        /// External initramfs, omitted when the probe is embedded in the kernel.
        #[arg(long, value_name = "PATH")]
        initramfs: Option<PathBuf>,
        #[arg(long)]
        cancel_while_starting: bool,
        #[arg(long)]
        cancel_helper_after_spawn: bool,
        #[arg(long)]
        translated_workload: bool,
        #[arg(long, value_name = "PATH")]
        vmmon: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        guest_kernel: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        guest_initramfs: Option<PathBuf>,
        #[arg(long, value_name = "PATH", default_value = DEFAULT_HOST_ROOT)]
        host_root: PathBuf,
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

    #[derive(Clone)]
    struct HelperInputs {
        vmmon: PathBuf,
        kernel: PathBuf,
        initramfs: PathBuf,
    }

    struct SourceSnapshot {
        root: PathBuf,
        bytes: Vec<u8>,
        sha256: [u8; 32],
        identity: SourceIdentity,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct SourceIdentity {
        device: u64,
        inode: u64,
        size: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
    }

    #[derive(Clone, Copy)]
    struct ProbeResponse {
        ioctl_result: i32,
        data: [u8; 1024],
    }

    #[derive(Clone, Debug)]
    enum StartCompletion {
        Pending,
        Succeeded,
        Failed(String),
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(|error| eyre!("initialize harness tracing: {error}"))?;
        if !args.kernel.is_file() {
            return Err(eyre!("kernel is not a regular file"));
        }
        if let Some(initramfs) = &args.initramfs {
            if !initramfs.is_file() {
                return Err(eyre!("initramfs is not a regular file"));
            }
        }
        let helper = helper_inputs(&args)?;
        if args.cancel_while_starting && helper.is_some() {
            return Err(eyre!(
                "--cancel-while-starting cannot be combined with helper qualification"
            ));
        }
        if args.cancel_helper_after_spawn && helper.is_none() {
            return Err(eyre!(
                "--cancel-helper-after-spawn requires helper qualification inputs"
            ));
        }
        if args.translated_workload && helper.is_none() {
            return Err(eyre!(
                "--translated-workload requires helper qualification inputs"
            ));
        }
        if args.cancel_while_starting && args.cancel_helper_after_spawn {
            return Err(eyre!("only one cancellation scenario may be selected"));
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
        runtime.block_on(run(args, helper, memory))
    }

    async fn run(args: Args, helper: Option<HelperInputs>, memory: u64) -> Result<()> {
        if args.initramfs.is_none() && !args.cancel_while_starting {
            return run_embedded(args, helper).await;
        }
        let started = Instant::now();
        let acquisition_deadline = started + ACQUISITION_TIMEOUT;
        let source = helper
            .as_ref()
            .map(|_| SourceSnapshot::capture(&args.host_root))
            .transpose()?;

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
        if let Some(initramfs) = args.initramfs {
            boot_loader.set_initial_ramdisk(initramfs);
        }
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
        let mut data = [0; 1024];
        data.copy_from_slice(frame.payload);
        let response = ProbeResponse {
            ioctl_result: frame.header.result,
            data,
        };

        let helper_report = match (helper, source) {
            (Some(helper), Some(source)) => {
                source.verify_unchanged()?;
                Some(
                    qualify_helper(
                        helper,
                        &source,
                        response,
                        args.cancel_helper_after_spawn,
                        args.translated_workload,
                    )
                    .await?,
                )
            }
            (None, None) => None,
            _ => return Err(eyre!("helper qualification inputs became inconsistent")),
        };

        let (helper_qualification, workload) = match helper_report {
            Some(HelperOutcome::Passed(FrameOutcome {
                translated_workload: true,
            })) => (
                "passed",
                "translated_workload=passed translated_workload_exit=37 translated_workload_stdout=SILO_X86_STATIC_OK\\n",
            ),
            Some(HelperOutcome::Passed(FrameOutcome {
                translated_workload: false,
            })) => ("passed", "translated_workload=not-requested"),
            Some(HelperOutcome::Cancelled) => ("cancelled-reaped", "translated_workload=not-completed"),
            None => ("not-requested", "translated_workload=not-requested"),
        };
        println!(
            "host_harness_pid={} guest_pid=1 status={} payload_len={} cpu_count=1 memory_bytes={} acquisition_ms={} cleanup_ms={} diagnostic_bytes={} diagnostic_retained={} resources=disks:0,network:0,vsock:0,balloon:0 serial_ports=hvc0:diagnostic,hvc1:raw share=rosetta start_callback={} vz_xpc_pid=not-observed cleanup=stopped-released helper_qualification={} {}",
            std::process::id(),
            response.ioctl_result,
            response.data.len(),
            memory,
            cleanup_started.duration_since(started).as_millis(),
            cleanup_started.elapsed().as_millis(),
            diagnostic_stats.total,
            diagnostic_stats.retained.len(),
            cleanup.start_completion,
            helper_qualification,
            workload,
        );
        Ok(())
    }

    async fn run_embedded(args: Args, helper: Option<HelperInputs>) -> Result<()> {
        let source = helper
            .as_ref()
            .map(|_| SourceSnapshot::capture(&args.host_root))
            .transpose()?;
        let prepared = crate::rosetta::acquire(
            fs::canonicalize(&args.kernel)?,
            Instant::now() + ACQUISITION_TIMEOUT,
            tokio_util::sync::CancellationToken::new(),
        )
        .await?;
        let response = ProbeResponse {
            ioctl_result: prepared.launch.ioctl_result(),
            data: *prepared.launch.data().as_bytes(),
        };
        let mut qualification = "not-requested";
        let mut translated = false;
        if let (Some(helper), Some(source)) = (helper, source) {
            source.verify_unchanged()?;
            if &source.sha256 != prepared.launch.translator_sha256()
                || source.root != prepared.launch.host_root()
            {
                return Err(eyre!("helper translator differs from captured translator"));
            }
            match qualify_helper(
                helper,
                &source,
                response,
                args.cancel_helper_after_spawn,
                args.translated_workload,
            )
            .await?
            {
                HelperOutcome::Passed(outcome) => {
                    qualification = "passed";
                    translated = outcome.translated_workload;
                }
                HelperOutcome::Cancelled => qualification = "cancelled-reaped",
            }
        }
        println!("runtime_acquisition=passed status={} payload_len={} cleanup=stopped-released helper_qualification={} translated_workload={}",
            response.ioctl_result, response.data.len(), qualification,
            if translated { "passed" } else { "not-completed" });
        Ok(())
    }

    fn helper_inputs(args: &Args) -> Result<Option<HelperInputs>> {
        match (&args.vmmon, &args.guest_kernel, &args.guest_initramfs) {
            (None, None, None) => Ok(None),
            (Some(vmmon), Some(kernel), Some(initramfs)) => {
                for (kind, path) in [
                    ("vmmon worker executable", vmmon),
                    ("guest kernel", kernel),
                    ("guest initramfs", initramfs),
                ] {
                    if !path.is_file() {
                        return Err(eyre!("{kind} is not a regular file"));
                    }
                }
                Ok(Some(HelperInputs {
                    vmmon: vmmon.clone(),
                    kernel: kernel.clone(),
                    initramfs: initramfs.clone(),
                }))
            }
            _ => Err(eyre!(
                "--vmmon, --guest-kernel and --guest-initramfs must be supplied together"
            )),
        }
    }

    impl SourceSnapshot {
        fn capture(root: &Path) -> Result<Self> {
            if !root.is_absolute() {
                return Err(eyre!("translator source root must be absolute"));
            }
            let path = root.join("rosetta");
            let metadata = fs::symlink_metadata(&path).wrap_err("inspect translator source")?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.permissions().mode() & 0o111 == 0
            {
                return Err(eyre!("translator source must be a regular executable file"));
            }
            let size = usize::try_from(metadata.len())
                .map_err(|_| eyre!("translator source size does not fit usize"))?;
            if size == 0 || size > MAX_TRANSLATOR_SIZE {
                return Err(eyre!("translator source exceeds the bounded size policy"));
            }
            let bytes = fs::read(&path).wrap_err("read translator source snapshot")?;
            if bytes.len() != size {
                return Err(eyre!("translator source changed while reading"));
            }
            let identity = source_identity(&metadata);
            let after = fs::symlink_metadata(&path)
                .wrap_err("reinspect translator source after snapshot")?;
            if source_identity(&after) != identity {
                return Err(eyre!("translator source changed while reading"));
            }
            let sha256 = sha256(&bytes)?;
            Ok(Self {
                root: root.to_path_buf(),
                bytes,
                sha256,
                identity,
            })
        }

        fn verify_unchanged(&self) -> Result<()> {
            let path = self.root.join("rosetta");
            let metadata = fs::symlink_metadata(&path)
                .wrap_err("reinspect translator source after acquisition")?;
            let current = fs::read(path).wrap_err("re-read translator source after acquisition")?;
            if source_identity(&metadata) != self.identity || current != self.bytes {
                return Err(eyre!("translator source changed during acquisition"));
            }
            Ok(())
        }
    }

    fn source_identity(metadata: &fs::Metadata) -> SourceIdentity {
        SourceIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }

    async fn qualify_helper(
        inputs: HelperInputs,
        source: &SourceSnapshot,
        response: ProbeResponse,
        cancel_after_spawn: bool,
        translated_workload: bool,
    ) -> Result<HelperOutcome> {
        let config = RosettaLaunchConfig::new(
            source.root.clone(),
            source.sha256,
            response.ioctl_result,
            response.data,
        )
        .wrap_err("construct bounded helper configuration")?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut worker = tokio::task::spawn_blocking(move || {
            run_helper(
                inputs,
                config,
                response,
                worker_cancel,
                started_tx,
                translated_workload,
            )
        });

        if cancel_after_spawn {
            if started_rx.await.is_err() {
                return match join_helper_worker(worker.await)? {
                    HelperOutcome::Passed(outcome) => Ok(HelperOutcome::Passed(outcome)),
                    HelperOutcome::Cancelled => Err(eyre!(
                        "helper qualification cancelled before spawn notification"
                    )),
                };
            }
            cancel.store(true, Ordering::Release);
            return match join_helper_worker(worker.await)? {
                HelperOutcome::Cancelled => Ok(HelperOutcome::Cancelled),
                HelperOutcome::Passed(_) => Err(eyre!(
                    "helper qualification completed before cancellation was observed"
                )),
            };
        }

        tokio::select! {
            result = &mut worker => match join_helper_worker(result)? {
                HelperOutcome::Passed(outcome) => Ok(HelperOutcome::Passed(outcome)),
                HelperOutcome::Cancelled => Err(eyre!("helper qualification cancelled unexpectedly")),
            },
            signal = tokio::signal::ctrl_c() => {
                signal.wrap_err("listen for helper qualification cancellation")?;
                cancel.store(true, Ordering::Release);
                match join_helper_worker(worker.await)? {
                    HelperOutcome::Cancelled => Err(eyre!(
                        "helper qualification cancelled; krun worker cleaned up and reaped"
                    )),
                    HelperOutcome::Passed(_) => Err(eyre!(
                        "helper qualification completed before cancellation was observed"
                    )),
                }
            }
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum HelperOutcome {
        Passed(FrameOutcome),
        Cancelled,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FrameOutcome {
        translated_workload: bool,
    }

    fn join_helper_worker(
        result: std::result::Result<Result<HelperOutcome>, tokio::task::JoinError>,
    ) -> Result<HelperOutcome> {
        result.map_err(|error| eyre!("helper qualification worker failed: {error}"))?
    }

    fn run_helper(
        inputs: HelperInputs,
        config: RosettaLaunchConfig,
        response: ProbeResponse,
        cancel: Arc<AtomicBool>,
        started: tokio::sync::oneshot::Sender<()>,
        translated_workload: bool,
    ) -> Result<HelperOutcome> {
        let mut vm = Worker::start(
            &inputs.vmmon,
            krun::KrunConfig {
                cpus: 1,
                memory_mib: 512,
                kernel: Some(inputs.kernel.clone()),
                initramfs: Some(inputs.initramfs.clone()),
                cmdline: vec!["rdinit=/init console=hvc0 panic=0 quiet loglevel=0".to_string()],
                stdio_console: true,
                balloon: true,
                rosetta: Some(config),
                ..krun::KrunConfig::default()
            },
        )
        .wrap_err("start krun responder worker")?;
        let (mut reader, writer) = vm.serial().wrap_err("take worker console")?;
        let flags = OFlag::from_bits_retain(
            fcntl(reader.as_fd(), FcntlArg::F_GETFL).wrap_err("read console flags")?,
        );
        fcntl(reader.as_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
            .wrap_err("make helper console nonblocking")?;
        let _ = started.send(());
        let qualification = receive_exerciser_frame(
            &mut vm,
            &mut reader,
            &response,
            &cancel,
            translated_workload,
        );
        let completed = qualification.as_ref().is_ok_and(Option::is_some);
        let cleanup = if completed {
            request_helper_shutdown(&mut vm, &mut reader)
        } else {
            cancel_and_reap_helper(&mut vm, &mut reader)
        };
        drop(reader);
        drop(writer);
        let outcome = qualification?;
        cleanup?;
        Ok(match outcome {
            Some(outcome) => HelperOutcome::Passed(outcome),
            None => HelperOutcome::Cancelled,
        })
    }

    fn receive_exerciser_frame(
        vm: &mut Worker,
        reader: &mut fs::File,
        response: &ProbeResponse,
        cancel: &AtomicBool,
        translated_workload: bool,
    ) -> Result<Option<FrameOutcome>> {
        let deadline = StdInstant::now() + HELPER_TIMEOUT;
        let mut decoder = ExerciserDecoder::new();
        let mut buffer = [0; 4096];
        let mut console_bytes = 0_u64;
        let mut diagnostics = Vec::with_capacity(HELPER_DIAGNOSTIC_LIMIT);
        while !decoder.is_complete() {
            if cancel.load(Ordering::Acquire) {
                return Ok(None);
            }
            match reader.read(&mut buffer) {
                Ok(0) => {}
                Ok(count) => {
                    console_bytes = console_bytes.saturating_add(count as u64);
                    for byte in &buffer[..count] {
                        decoder
                            .push(core::slice::from_ref(byte))
                            .map_err(|error| eyre!("invalid exerciser frame: {error:?}"))?;
                        if decoder.received_len() == 0
                            && diagnostics.len() < HELPER_DIAGNOSTIC_LIMIT
                        {
                            diagnostics.push(*byte);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {}
                Err(error) => return Err(error).wrap_err("read helper console"),
            }

            let now = StdInstant::now();
            if let Some(status) = vm.try_wait().wrap_err("poll krun helper")? {
                return Err(eyre!(
                    "krun helper exited before the shutdown request: {status}; console_bytes={console_bytes} frame_bytes={} diagnostics={}",
                    decoder.received_len(),
                    String::from_utf8_lossy(&diagnostics).escape_debug()
                ));
            }
            if now >= deadline {
                return Err(eyre!(
                    "krun worker exerciser timed out; diagnostics={}",
                    String::from_utf8_lossy(&diagnostics).escape_debug()
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }

        let frame = decoder
            .finish()
            .map_err(|error| eyre!("invalid exerciser frame: {error:?}"))?;
        let expected_checks = FILESYSTEM_CHECKS
            | if translated_workload {
                CHECK_TRANSLATED_WORKLOAD
            } else {
                0
            };
        if frame.checks != expected_checks {
            return Err(eyre!(
                "guest checks differ from the requested qualification mode"
            ));
        }
        if frame.ioctl_result != response.ioctl_result {
            return Err(eyre!("guest ioctl status differs from the captured status"));
        }
        if frame.payload != &response.data {
            return Err(eyre!("guest ioctl data differs from the captured response"));
        }
        Ok(Some(FrameOutcome {
            translated_workload: frame.checks & CHECK_TRANSLATED_WORKLOAD != 0,
        }))
    }

    fn request_helper_shutdown(vm: &mut Worker, console: &mut fs::File) -> Result<()> {
        if let Some(status) = vm.try_wait().wrap_err("poll krun worker")? {
            return Err(eyre!(
                "krun worker exited before the shutdown request: {status}"
            ));
        }
        if let Err(error) = vm.shutdown() {
            force_reap_helper(vm)?;
            return Err(error).wrap_err("request krun worker shutdown");
        }
        match wait_for_helper_with_console(vm, console, HELPER_CLEANUP_TIMEOUT) {
            Ok(Some(status)) => require_successful_helper_exit(status),
            Ok(None) => {
                force_reap_helper(vm)?;
                Err(eyre!("krun worker did not exit after the shutdown request"))
            }
            Err(error) => {
                force_reap_helper(vm)?;
                Err(error)
            }
        }
    }

    fn cancel_and_reap_helper(vm: &mut Worker, console: &mut fs::File) -> Result<()> {
        if let Some(status) = vm.try_wait().wrap_err("poll krun worker")? {
            return require_cancelled_helper_exit(status);
        }
        let shutdown_error = vm.shutdown().err();
        if shutdown_error.is_none() {
            match wait_for_helper_with_console(vm, console, HELPER_CLEANUP_TIMEOUT) {
                Ok(Some(status)) => return require_cancelled_helper_exit(status),
                Ok(None) => {}
                Err(error) => {
                    force_reap_helper(vm)?;
                    return Err(error);
                }
            }
        }
        force_reap_helper(vm)?;
        if let Some(error) = shutdown_error {
            return Err(error).wrap_err("request krun worker shutdown");
        }
        Ok(())
    }

    fn wait_for_helper_with_console(
        vm: &mut Worker,
        console: &mut fs::File,
        timeout: Duration,
    ) -> Result<Option<ExitStatus>> {
        let deadline = StdInstant::now() + timeout;
        let mut buffer = [0; 4096];
        loop {
            if let Some(status) = vm.try_wait().wrap_err("poll krun worker")? {
                return Ok(Some(status));
            }
            match console.read(&mut buffer) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {}
                Err(error) => return Err(error).wrap_err("drain helper console during shutdown"),
            }
            if StdInstant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn require_successful_helper_exit(status: ExitStatus) -> Result<()> {
        if status.success() {
            Ok(())
        } else {
            Err(eyre!("krun worker exited unsuccessfully: {status}"))
        }
    }

    fn require_cancelled_helper_exit(status: ExitStatus) -> Result<()> {
        if status.success() || matches!(status.signal(), Some(libc::SIGTERM) | Some(libc::SIGKILL))
        {
            Ok(())
        } else {
            Err(eyre!(
                "krun worker exited unexpectedly during cancellation: {status}"
            ))
        }
    }

    fn force_reap_helper(vm: &mut Worker) -> Result<()> {
        let kill_error = vm.kill().err();
        if wait_for_helper(vm, Duration::from_secs(2))?.is_none() {
            return Err(eyre!("krun worker was not reaped after kill"));
        }
        if let Some(error) = kill_error {
            return Err(error).wrap_err("kill krun worker after timeout");
        }
        Ok(())
    }

    fn wait_for_helper(vm: &mut Worker, timeout: Duration) -> Result<Option<ExitStatus>> {
        let deadline = StdInstant::now() + timeout;
        loop {
            if let Some(status) = vm.try_wait().wrap_err("poll krun worker")? {
                return Ok(Some(status));
            }
            if StdInstant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    // nix does not expose Apple's CommonCrypto digest API.
    #[link(name = "System")]
    unsafe extern "C" {
        fn CC_SHA256(data: *const c_void, len: u32, digest: *mut u8) -> *mut u8;
    }

    fn sha256(bytes: &[u8]) -> Result<[u8; 32]> {
        let len =
            u32::try_from(bytes.len()).map_err(|_| eyre!("translator source is too large"))?;
        let mut digest = [0; 32];
        let result = unsafe { CC_SHA256(bytes.as_ptr().cast(), len, digest.as_mut_ptr()) };
        if result != digest.as_mut_ptr() {
            return Err(eyre!("CommonCrypto SHA-256 failed"));
        }
        Ok(digest)
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

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;

        use clap::Parser;

        use crate::macos::Args;

        #[test]
        fn embedded_probe_needs_only_a_kernel() {
            let args = Args::try_parse_from(["harness", "--kernel", "rprobe"]).unwrap();
            assert_eq!(args.kernel, PathBuf::from("rprobe"));
            assert!(args.initramfs.is_none());
        }

        #[test]
        fn external_initramfs_remains_explicit() {
            let args = Args::try_parse_from([
                "harness",
                "--kernel",
                "Image",
                "--initramfs",
                "probe.cpio.gz",
            ])
            .unwrap();
            assert_eq!(args.initramfs, Some(PathBuf::from("probe.cpio.gz")));
        }
    }
}

#[cfg(target_os = "macos")]
fn main() -> eyre::Result<()> {
    macos::main()
}

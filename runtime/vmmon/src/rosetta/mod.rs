use std::ffi::{c_void, CStr, CString};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use eyre::{eyre, Context};
use rprobe::frame::{Decoder, FrameError, SUCCESS_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
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
const MAX_TRANSLATOR_SIZE: usize = 128 * 1024 * 1024;
const MAX_PROBE_KERNEL_SIZE: usize = 128 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 64 * 1024;
const ERROR_DIAGNOSTIC_LIMIT: usize = 4096;
const HOST_ROOT: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux";

pub(crate) struct PreparedRosetta {
    pub(crate) launch: krun::RosettaLaunchConfig,
}

struct SourceSnapshot {
    root: PathBuf,
    bytes: Vec<u8>,
    sha256: [u8; 32],
    identity: SourceIdentity,
}

struct FileSnapshot {
    path: PathBuf,
    bytes: Vec<u8>,
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

struct DiagnosticStats {
    retained: Vec<u8>,
    total: u64,
}

pub(crate) async fn acquire(
    kernel: PathBuf,
    outer_deadline: Instant,
    cancelled: CancellationToken,
) -> eyre::Result<PreparedRosetta> {
    let started = Instant::now();
    let acquisition_deadline = (started + ACQUISITION_TIMEOUT).min(outer_deadline);
    let preflight = async {
        let snapshot = FileSnapshot::capture(&kernel, MAX_PROBE_KERNEL_SIZE, false).await?;
        require_available()?;
        let source = SourceSnapshot::capture(Path::new(HOST_ROOT)).await?;
        Ok::<_, eyre::Report>((snapshot, source))
    };
    let (kernel_snapshot, source) = tokio::select! {
        biased;
        () = cancelled.cancelled() => Err(eyre!("Rosetta source and asset validation cancelled")),
        result = tokio::time::timeout_at(acquisition_deadline, preflight) => match result {
            Ok(result) => result,
            Err(_) => Err(eyre!("Rosetta source and asset validation exceeded the acquisition deadline")),
        },
    }?;
    tracing::debug!(
        host_build = ?sysctl_string("kern.osversion").ok(),
        translator_sha256 = %encode_hex(&source.sha256),
        kernel_sha256 = %encode_hex(&sha256(&kernel_snapshot.bytes)?),
        kernel = %kernel.display(),
        "Rosetta acquisition inputs"
    );

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

    tokio::select! {
        biased;
        () = cancelled.cancelled() => {
            return Err(eyre!("Rosetta pre-probe validation cancelled"));
        }
        result = tokio::time::timeout_at(acquisition_deadline, async {
            kernel_snapshot.verify_unchanged().await?;
            source.verify_unchanged().await
        }) => match result {
            Ok(result) => result,
            Err(_) => Err(eyre!("Rosetta pre-probe validation exceeded the acquisition deadline")),
        }?
    }

    let diagnostic_port = SerialPortConfiguration::virtio_console()
        .wrap_err("construct Rosetta probe diagnostic serial port")?;
    let data_port = SerialPortConfiguration::virtio_console()
        .wrap_err("construct Rosetta probe data serial port")?;
    let mut diagnostic_stream = diagnostic_port
        .open_stream()
        .wrap_err("open Rosetta probe diagnostic stream")?;
    let mut data_stream = data_port
        .open_stream()
        .wrap_err("open Rosetta probe data stream")?;
    diagnostic_stream
        .shutdown()
        .await
        .wrap_err("close Rosetta probe diagnostic input")?;
    data_stream
        .shutdown()
        .await
        .wrap_err("close Rosetta probe data input")?;

    let mut boot_loader = LinuxBootLoader::new(kernel);
    boot_loader.set_command_line(if tracing::enabled!(tracing::Level::DEBUG) {
        "rdinit=/init console=hvc0 panic=0 loglevel=7"
    } else {
        "rdinit=/init console=hvc0 panic=0 loglevel=4"
    });
    let platform = GenericPlatform::new();
    platform.set_nested_virtualization_enabled(false);
    let mut filesystem = VirtioFileSystemDeviceConfiguration::new(agent_spec::ROSETTA_MOUNT_TAG)
        .wrap_err("construct Rosetta probe filesystem")?;
    filesystem.set_rosetta_share(
        LinuxRosettaDirectoryShare::new().wrap_err("construct Rosetta probe share")?,
    );
    let vm = VirtualMachine::builder()
        .wrap_err("construct Rosetta probe configuration")?
        .set_cpu_count(1)
        .set_memory_size(memory)
        .set_platform(platform)
        .set_boot_loader(boot_loader)
        .add_serial_port(diagnostic_port.clone())
        .add_serial_port(data_port.clone())
        .add_directory_share(filesystem)
        .build()
        .wrap_err("validate Rosetta probe configuration")?;
    if cancelled.is_cancelled() {
        return Err(eyre!("Rosetta probe start cancelled before ownership"));
    }

    let diagnostic_task = tokio::spawn(drain_diagnostics(diagnostic_stream));
    let mut states = vm.subscribe_state();
    let start_vm = vm.clone();
    let start_task = tokio::spawn(async move { start_vm.start().await });
    tracing::info!(
        event = "rosetta_probe_start_requested",
        "Rosetta acquisition probe start requested"
    );
    let acquisition = tokio::select! {
        result = tokio::time::timeout_at(acquisition_deadline, async {
            wait_for_state(&vm, &mut states, VirtualMachineState::Running).await?;
            receive_frame(&mut data_stream).await
        }) => match result {
            Ok(result) => result,
            Err(_) => Err(eyre!("Rosetta probe acquisition timed out")),
        },
        () = cancelled.cancelled() => Err(eyre!("Rosetta probe acquisition cancelled")),
    };

    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let cleanup = cleanup_with_start(&vm, &mut states, start_task, cleanup_deadline).await;
    if cleanup.is_ok() {
        tracing::info!(
            event = "rosetta_probe_stopped",
            "Rosetta acquisition probe stopped"
        );
    }
    drop(vm);
    drop(diagnostic_port);
    drop(data_port);
    let trailing = check_trailing_data(&mut data_stream, cleanup_deadline).await;
    drop(data_stream);
    let mut diagnostic_task = diagnostic_task;
    let diagnostics = match tokio::time::timeout_at(cleanup_deadline, &mut diagnostic_task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(eyre!("Rosetta probe diagnostic task failed: {error}")),
        Err(_) => {
            diagnostic_task.abort();
            let _ = diagnostic_task.await;
            Err(eyre!(
                "Rosetta probe diagnostic drain did not finish during cleanup"
            ))
        }
    };

    let (decoder, diagnostics) = finish_acquisition(acquisition, cleanup, trailing, diagnostics)
        .inspect_err(|error| tracing::error!(error = %error, "Rosetta acquisition failed"))?;
    tracing::info!(
        event = "rosetta_probe_released",
        "Rosetta acquisition probe resources released"
    );
    let frame = decoder
        .finish()
        .map_err(|error| eyre!("Rosetta probe frame failed final validation: {error:?}"))?;
    tracing::debug!(header = ?frame.header, "Rosetta response decoded");
    if frame.header.result < 0 {
        return Err(acquisition_error(
            eyre!(
                "Rosetta probe ioctl failed status={} errno={} payload_len={}",
                frame.header.result,
                frame.header.errno,
                frame.payload.len()
            ),
            &diagnostics,
        ));
    }
    let data: [u8; 1024] = frame
        .payload
        .try_into()
        .map_err(|_| eyre!("successful Rosetta probe frame has invalid payload length"))?;
    tokio::select! {
        result = tokio::time::timeout_at(acquisition_deadline, async {
            kernel_snapshot.verify_unchanged().await?;
            source.verify_unchanged().await
        }) => match result {
            Ok(result) => result,
            Err(_) => Err(eyre!("Rosetta post-acquisition validation exceeded the acquisition deadline")),
        },
        () = cancelled.cancelled() => Err(eyre!("Rosetta post-acquisition validation cancelled")),
    }?;
    tracing::debug!(result = frame.header.result, payload_len = data.len(),
        payload_sha256 = %encode_hex(&sha256(&data)?), "Rosetta capture validated");
    let launch =
        krun::RosettaLaunchConfig::new(source.root, source.sha256, frame.header.result, data)
            .wrap_err("construct captured Rosetta launch configuration")?;
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        "Rosetta acquisition succeeded"
    );
    Ok(PreparedRosetta { launch })
}

fn finish_acquisition(
    acquisition: eyre::Result<Decoder>,
    cleanup: eyre::Result<()>,
    trailing: eyre::Result<()>,
    diagnostics: eyre::Result<DiagnosticStats>,
) -> eyre::Result<(Decoder, DiagnosticStats)> {
    let mut errors = Vec::new();
    if let Err(error) = &acquisition {
        errors.push(format!("acquisition: {error:#}"));
    }
    for (stage, result) in [("cleanup", cleanup), ("trailing-data validation", trailing)] {
        if let Err(error) = result {
            errors.push(format!("{stage}: {error:#}"));
        }
    }
    if let Err(error) = &diagnostics {
        errors.push(format!("diagnostics: {error:#}"));
    }
    if !errors.is_empty() {
        let error = eyre!("Rosetta probe failed: {}", errors.join("; "));
        return Err(match &diagnostics {
            Ok(stats) => acquisition_error(error, stats),
            Err(_) => error,
        });
    }
    Ok((acquisition?, diagnostics?))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn require_available() -> eyre::Result<()> {
    match vz::rosetta_availability() {
        RosettaAvailability::Installed => Ok(()),
        RosettaAvailability::NotInstalled => Err(eyre!(
            "Rosetta for Linux VMs is not installed; install it explicitly before retrying"
        )),
        RosettaAvailability::NotSupported => {
            Err(eyre!("Rosetta for Linux VMs is not supported on this host"))
        }
    }
}

impl SourceSnapshot {
    async fn capture(root: &Path) -> eyre::Result<Self> {
        if !root.is_absolute() || tokio::fs::canonicalize(root).await? != root {
            return Err(eyre!(
                "Rosetta source root is not the canonical expected directory"
            ));
        }
        let path = root.join("rosetta");
        let snapshot = FileSnapshot::capture(&path, MAX_TRANSLATOR_SIZE, true).await?;
        let sha256 = sha256(&snapshot.bytes)?;
        Ok(Self {
            root: root.to_path_buf(),
            bytes: snapshot.bytes,
            sha256,
            identity: snapshot.identity,
        })
    }

    async fn verify_unchanged(&self) -> eyre::Result<()> {
        let current =
            FileSnapshot::capture(&self.root.join("rosetta"), MAX_TRANSLATOR_SIZE, true).await?;
        if current.identity != self.identity || current.bytes != self.bytes {
            return Err(eyre!("Rosetta source changed during acquisition"));
        }
        Ok(())
    }
}

impl FileSnapshot {
    async fn capture(path: &Path, maximum_size: usize, executable: bool) -> eyre::Result<Self> {
        let canonical = tokio::fs::canonicalize(path)
            .await
            .wrap_err_with(|| format!("canonicalize {}", path.display()))?;
        if canonical != path {
            return Err(eyre!("{} is not a canonical regular file", path.display()));
        }
        let before = tokio::fs::symlink_metadata(path)
            .await
            .wrap_err_with(|| format!("inspect {}", path.display()))?;
        if !before.file_type().is_file() || before.file_type().is_symlink() {
            return Err(eyre!("{} is not a regular file", path.display()));
        }
        if executable && before.permissions().mode() & 0o111 == 0 {
            return Err(eyre!("{} is not executable", path.display()));
        }
        let size = usize::try_from(before.len())
            .map_err(|_| eyre!("{} size does not fit usize", path.display()))?;
        if size == 0 || size > maximum_size {
            return Err(eyre!("{} exceeds its bounded size policy", path.display()));
        }
        let file = tokio::fs::File::open(path)
            .await
            .wrap_err_with(|| format!("open {}", path.display()))?;
        let mut bytes = Vec::with_capacity(size);
        file.take(maximum_size as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .wrap_err_with(|| format!("read {}", path.display()))?;
        if bytes.len() != size || bytes.len() > maximum_size {
            return Err(eyre!("{} changed while reading", path.display()));
        }
        let after = tokio::fs::symlink_metadata(path)
            .await
            .wrap_err_with(|| format!("reinspect {}", path.display()))?;
        let identity = source_identity(&before);
        if source_identity(&after) != identity {
            return Err(eyre!("{} changed while reading", path.display()));
        }
        Ok(Self {
            path: path.to_path_buf(),
            bytes,
            identity,
        })
    }

    async fn verify_unchanged(&self) -> eyre::Result<()> {
        let current = Self::capture(&self.path, self.bytes.len(), false).await?;
        if current.identity != self.identity || current.bytes != self.bytes {
            return Err(eyre!("{} changed during acquisition", self.path.display()));
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

async fn receive_frame(stream: &mut SerialPortStream) -> eyre::Result<Decoder> {
    let mut decoder = Decoder::new();
    let mut buffer = [0_u8; SUCCESS_LEN];
    while !decoder.is_complete() {
        let maximum = decoder
            .expected_len()
            .unwrap_or(SUCCESS_LEN)
            .saturating_sub(decoder.received_len());
        if maximum == 0 {
            return Err(eyre!("Rosetta probe frame made no progress"));
        }
        let count = stream
            .read(&mut buffer[..maximum])
            .await
            .wrap_err("read Rosetta probe frame")?;
        if count == 0 {
            return Err(eyre!("Rosetta probe frame ended before completion"));
        }
        tracing::trace!(target: "rosetta_wire", offset = decoder.received_len(), count,
            bytes = %encode_hex(&buffer[..count]), "Rosetta frame received");
        decoder.push(&buffer[..count]).map_err(frame_error)?;
    }
    Ok(decoder)
}

async fn cleanup_with_start(
    vm: &VirtualMachine,
    states: &mut watch::Receiver<VirtualMachineState>,
    start_task: tokio::task::JoinHandle<Result<(), vz::VzError>>,
    deadline: Instant,
) -> eyre::Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = await_start_task(start_task, deadline).await {
        errors.push(error.to_string());
    }
    if let Err(error) = cleanup_vm(vm, states, deadline).await {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(eyre!(errors.join("; ")))
    }
}

async fn await_start_task(
    start_task: tokio::task::JoinHandle<Result<(), vz::VzError>>,
    deadline: Instant,
) -> eyre::Result<()> {
    let mut start_task = start_task;
    match tokio::time::timeout_at(deadline, &mut start_task).await {
        Ok(Ok(result)) => result.wrap_err("VZ probe start callback failed"),
        Ok(Err(error)) => Err(eyre!("VZ probe start callback task failed: {error}")),
        Err(_) => {
            start_task.abort();
            let _ = start_task.await;
            Err(eyre!(
                "VZ probe start callback was not released during cleanup"
            ))
        }
    }
}

async fn cleanup_vm(
    vm: &VirtualMachine,
    states: &mut watch::Receiver<VirtualMachineState>,
    deadline: Instant,
) -> eyre::Result<()> {
    let mut errors = Vec::new();
    if matches!(
        vm.state(),
        VirtualMachineState::Running | VirtualMachineState::Paused
    ) {
        match tokio::time::timeout_at(deadline, vm.stop()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("direct VZ probe stop failed: {error}")),
            Err(_) => errors.push("direct VZ probe stop timed out".to_string()),
        }
    }
    if vm.state() != VirtualMachineState::Error {
        match tokio::time::timeout_at(
            deadline,
            wait_for_state(vm, states, VirtualMachineState::Stopped),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(error.to_string()),
            Err(_) => errors.push("VZ probe stopped-state wait timed out".to_string()),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(eyre!(errors.join("; ")))
    }
}

async fn wait_for_state(
    vm: &VirtualMachine,
    states: &mut watch::Receiver<VirtualMachineState>,
    target: VirtualMachineState,
) -> eyre::Result<()> {
    loop {
        let state = vm.state();
        tracing::debug!(?state, ?target, "Rosetta probe state");
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
            .map_err(|_| eyre!("VZ probe state stream closed while awaiting {target}"))?;
    }
}

async fn check_trailing_data(stream: &mut SerialPortStream, deadline: Instant) -> eyre::Result<()> {
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout_at(deadline, stream.read(&mut byte))
        .await
        .map_err(|_| eyre!("Rosetta probe raw serial EOF check timed out after release"))?
        .wrap_err("check Rosetta probe raw serial trailing data")?;
    if count == 0 {
        Ok(())
    } else {
        tracing::trace!(target: "rosetta_wire", bytes = %encode_hex(&byte[..count]), "Rosetta unexpected trailing data");
        Err(eyre!("Rosetta probe raw serial contained trailing data"))
    }
}

async fn drain_diagnostics(mut stream: SerialPortStream) -> eyre::Result<DiagnosticStats> {
    let mut retained = Vec::with_capacity(DIAGNOSTIC_LIMIT);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .wrap_err("drain Rosetta probe diagnostics")?;
        if count == 0 {
            return Ok(DiagnosticStats { retained, total });
        }
        total = total.saturating_add(count as u64);
        let keep = (DIAGNOSTIC_LIMIT - retained.len()).min(count);
        if keep > 0 {
            tracing::debug!(offset = retained.len(),
                diagnostic = %String::from_utf8_lossy(&buffer[..keep]).escape_debug(),
                "Rosetta guest diagnostic");
        }
        if keep < count && retained.len() < DIAGNOSTIC_LIMIT {
            tracing::debug!(
                limit = DIAGNOSTIC_LIMIT,
                "Rosetta diagnostic logging truncated; continuing to drain"
            );
        }
        retained.extend_from_slice(&buffer[..keep]);
    }
}

fn acquisition_error(error: eyre::Report, diagnostics: &DiagnosticStats) -> eyre::Report {
    let retained = &diagnostics.retained[..diagnostics.retained.len().min(ERROR_DIAGNOSTIC_LIMIT)];
    eyre!(
        "{error}; probe diagnostics bytes={} retained={:?}",
        diagnostics.total,
        String::from_utf8_lossy(retained).escape_debug().to_string()
    )
}

fn frame_error(error: FrameError) -> eyre::Report {
    eyre!("invalid Rosetta probe frame: {error:?}")
}

// nix does not expose Apple's CommonCrypto digest API.
#[link(name = "System")]
unsafe extern "C" {
    fn CC_SHA256(data: *const c_void, len: u32, digest: *mut u8) -> *mut u8;
}

fn sha256(bytes: &[u8]) -> eyre::Result<[u8; 32]> {
    let len = u32::try_from(bytes.len()).map_err(|_| eyre!("Rosetta source is too large"))?;
    let mut digest = [0_u8; 32];
    let result = unsafe { CC_SHA256(bytes.as_ptr().cast(), len, digest.as_mut_ptr()) };
    if result != digest.as_mut_ptr() {
        return Err(eyre!("CommonCrypto SHA-256 failed"));
    }
    Ok(digest)
}

fn sysctl_string(name: &str) -> eyre::Result<String> {
    let name = CString::new(name).map_err(|_| eyre!("invalid sysctl name"))?;
    let mut length = 0_usize;
    // nix does not expose sysctlbyname on current macOS targets.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length == 0
    {
        return Err(eyre!(
            "read host build size: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut value = vec![0_u8; length];
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(eyre!(
            "read host build: {}",
            std::io::Error::last_os_error()
        ));
    }
    let value = CStr::from_bytes_until_nul(&value[..length])
        .map_err(|_| eyre!("host build sysctl was not NUL terminated"))?;
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| eyre!("host build sysctl was not UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use crate::rosetta::{acquire, finish_acquisition, DiagnosticStats, FileSnapshot};

    #[test]
    fn acquisition_error_preserves_cleanup_failure_and_guest_diagnostics() {
        let result = finish_acquisition(
            Err(eyre::eyre!("bad frame")),
            Err(eyre::eyre!("stop failed")),
            Err(eyre::eyre!("trailing byte")),
            Ok(DiagnosticStats {
                retained: b"guest failed".to_vec(),
                total: 12,
            }),
        );
        let error = result.err().expect("must fail").to_string();
        for context in ["bad frame", "stop failed", "trailing byte", "guest failed"] {
            assert!(error.contains(context), "missing {context}: {error}");
        }
    }

    #[tokio::test]
    async fn single_kernel_snapshot_rejects_replacement_and_symlinks() {
        let directory =
            std::env::temp_dir().join(format!("rprobe-snapshot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let directory = std::fs::canonicalize(directory).unwrap();
        let kernel = directory.join("rprobe");
        std::fs::write(&kernel, b"kernel-one").unwrap();
        let snapshot = FileSnapshot::capture(&kernel, 1024, false).await.unwrap();
        snapshot.verify_unchanged().await.unwrap();
        std::fs::write(&kernel, b"kernel-two").unwrap();
        assert!(snapshot.verify_unchanged().await.is_err());
        assert!(FileSnapshot::capture(&kernel, 2, false).await.is_err());
        let link = directory.join("link");
        std::os::unix::fs::symlink(&kernel, &link).unwrap();
        assert!(FileSnapshot::capture(&link, 1024, false).await.is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn cancellation_wins_before_probe_asset_validation_or_vm_creation() {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let result = acquire(
            PathBuf::from("invalid-kernel"),
            tokio::time::Instant::now() + Duration::from_secs(1),
            cancelled,
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("pre-cancelled acquisition must stop before validation"),
        };

        assert!(error
            .to_string()
            .contains("source and asset validation cancelled"));
    }
}

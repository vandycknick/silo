use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use thiserror::Error;

use crate::release_target::{BuildProfile, ReleaseTarget, ReleaseTargetDescriptor};

const EXECUTABLE_MODE: u32 = 0o755;
const READABLE_MODE: u32 = 0o644;
const MAX_INIT_SIZE: u64 = 64 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct StageRuntimeOptions {
    pub(crate) target: ReleaseTarget,
    pub(crate) profile: BuildProfile,
    pub(crate) kernel: PathBuf,
    pub(crate) target_dir: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum StageRuntimeError {
    #[error("kernel path must be absolute: {path}")]
    RelativeKernel { path: PathBuf },
    #[error(
        "cannot stage {requested} artifacts on this host; target-native staging requires {host}"
    )]
    HostTargetMismatch {
        requested: &'static str,
        host: &'static str,
    },
    #[error("invalid runtime component {component} at {path}: {reason}")]
    InvalidComponent {
        component: &'static str,
        path: PathBuf,
        reason: String,
    },
    #[error("failed to {operation} {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

pub(crate) fn stage_runtime(options: &StageRuntimeOptions) -> Result<PathBuf, StageRuntimeError> {
    stage_runtime_for_host(options, host_release_target())
}

pub(crate) fn validate_kernel(path: &Path, target: ReleaseTarget) -> Result<(), StageRuntimeError> {
    let source = ComponentSource::readable("kernel", path.to_path_buf(), "assets/kernel-default");
    require_regular_file(&source)?;
    validate_component(&source, target.descriptor())
}

fn stage_runtime_for_host(
    options: &StageRuntimeOptions,
    host_target: ReleaseTarget,
) -> Result<PathBuf, StageRuntimeError> {
    if options.target != host_target {
        return Err(StageRuntimeError::HostTargetMismatch {
            requested: options.target.descriptor().name,
            host: host_target.descriptor().name,
        });
    }
    if !options.kernel.is_absolute() {
        return Err(StageRuntimeError::RelativeKernel {
            path: options.kernel.clone(),
        });
    }

    let descriptor = options.target.descriptor();
    let profile_dir = options.target_dir.join(options.profile.to_string());
    let assets_dir = options.target_dir.join("resources/assets");
    let sources = [
        ComponentSource::executable("vmmon", profile_dir.join("vmmon"), "bin/vmmon"),
        ComponentSource::executable("netd", profile_dir.join("netd"), "bin/netd"),
        ComponentSource::executable("krun", profile_dir.join("krun"), "bin/krun"),
        ComponentSource::readable("kernel", options.kernel.clone(), "assets/kernel-default"),
        ComponentSource::readable(
            "initramfs",
            assets_dir.join("initramfs"),
            "assets/initramfs",
        ),
        ComponentSource::executable("agent", assets_dir.join("agent"), "assets/agent"),
    ];

    for source in &sources {
        require_regular_file(source)?;
        validate_component(source, descriptor)?;
    }

    let stage_dir = descriptor.stage_dir_in(&options.target_dir, options.profile);
    let temporary_dir = temporary_stage_dir(&stage_dir)?;
    let result = (|| {
        create_directory(&temporary_dir)?;
        create_directory(&temporary_dir.join("bin"))?;
        create_directory(&temporary_dir.join("assets"))?;
        for source in &sources {
            let destination = temporary_dir.join(source.destination);
            copy_file(source, &destination)?;
            set_mode(&destination, source.mode)?;
            let copied = ComponentSource {
                name: source.name,
                source: destination,
                destination: source.destination,
                mode: source.mode,
            };
            require_regular_file(&copied)?;
            validate_component(&copied, descriptor)?;
        }
        validate_staged_tree(&temporary_dir)?;
        replace_stage_directory(&temporary_dir, &stage_dir)?;
        Ok(stage_dir.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary_dir);
    }
    result
}

fn host_release_target() -> ReleaseTarget {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        ReleaseTarget::DarwinArm64
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        ReleaseTarget::LinuxAmd64Gnu
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        ReleaseTarget::LinuxArm64Gnu
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    )))]
    compile_error!("runtime staging supports only ADR 0012 release hosts");
}

#[derive(Debug)]
struct ComponentSource {
    name: &'static str,
    source: PathBuf,
    destination: &'static str,
    mode: u32,
}

impl ComponentSource {
    fn executable(name: &'static str, source: PathBuf, destination: &'static str) -> Self {
        Self {
            name,
            source,
            destination,
            mode: EXECUTABLE_MODE,
        }
    }

    fn readable(name: &'static str, source: PathBuf, destination: &'static str) -> Self {
        Self {
            name,
            source,
            destination,
            mode: READABLE_MODE,
        }
    }
}

fn require_regular_file(component: &ComponentSource) -> Result<(), StageRuntimeError> {
    let metadata = fs::symlink_metadata(&component.source).map_err(|source| {
        StageRuntimeError::InvalidComponent {
            component: component.name,
            path: component.source.clone(),
            reason: source.to_string(),
        }
    })?;
    if metadata.file_type().is_file() {
        return Ok(());
    }
    Err(StageRuntimeError::InvalidComponent {
        component: component.name,
        path: component.source.clone(),
        reason: "source is not a regular file".to_string(),
    })
}

fn validate_component(
    component: &ComponentSource,
    descriptor: ReleaseTargetDescriptor,
) -> Result<(), StageRuntimeError> {
    let expected = architecture_for_guest_target(descriptor.guest_target);
    match component.name {
        "vmmon" | "netd" | "krun" if descriptor.goos == "darwin" => {
            validate_macho(component, Architecture::Arm64)
        }
        "vmmon" | "netd" | "krun" => validate_elf(component, expected),
        "agent" => validate_elf(component, expected),
        "kernel" if expected == Architecture::Arm64 => validate_arm64_kernel(component),
        "kernel" => validate_elf(component, Architecture::X86_64),
        "initramfs" => validate_initramfs(component, expected),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Architecture {
    X86_64,
    Arm64,
}

fn architecture_for_guest_target(target: &str) -> Architecture {
    if target.starts_with("aarch64-") {
        Architecture::Arm64
    } else {
        Architecture::X86_64
    }
}

fn validate_elf(
    component: &ComponentSource,
    expected: Architecture,
) -> Result<(), StageRuntimeError> {
    let bytes = read_prefix(component, MAX_HEADER_BYTES)?;
    let file_size = file_size(component)?;
    if valid_elf_header(&bytes, file_size, expected) {
        return Ok(());
    }
    invalid_architecture(component, expected, "ELF")
}

fn validate_macho(
    component: &ComponentSource,
    expected: Architecture,
) -> Result<(), StageRuntimeError> {
    let bytes = read_prefix(component, 4096)?;
    let file_size = file_size(component)?;
    if expected == Architecture::Arm64 && valid_arm64_macho(&bytes, file_size) {
        return Ok(());
    }
    invalid_architecture(component, expected, "Mach-O")
}

fn valid_arm64_macho(bytes: &[u8], file_size: u64) -> bool {
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    if bytes.len() < 32 || bytes.get(..4) != Some(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return false;
    }
    let cpu_type = read_u32_le(bytes, 4);
    let file_type = read_u32_le(bytes, 12);
    let command_count = read_u32_le(bytes, 16);
    let command_bytes = read_u32_le(bytes, 20);
    let (Some(command_count), Some(command_bytes)) = (command_count, command_bytes) else {
        return false;
    };
    if cpu_type != Some(CPU_TYPE_ARM64)
        || file_type != Some(2)
        || command_count == 0
        || command_bytes < 8
    {
        return false;
    }
    let commands_end = 32_u64.saturating_add(u64::from(command_bytes));
    if commands_end > file_size || commands_end > bytes.len() as u64 {
        return false;
    }
    let mut offset = 32_usize;
    let mut executable_segment = false;
    for _ in 0..command_count {
        let Some(command) = read_u32_le(bytes, offset) else {
            return false;
        };
        let Some(command_size) = read_u32_le(bytes, offset + 4) else {
            return false;
        };
        if command_size < 8 {
            return false;
        }
        if command == 0x19 && command_size >= 72 {
            let file_offset = read_u64_le(bytes, offset + 40);
            let file_length = read_u64_le(bytes, offset + 48);
            let initial_protection = read_u32_le(bytes, offset + 60);
            let valid_segment = file_offset.zip(file_length).is_some_and(|(start, length)| {
                length > 0 && start.saturating_add(length) <= file_size
            });
            if !valid_segment {
                return false;
            }
            if initial_protection.is_some_and(|protection| protection & 0x4 != 0) {
                executable_segment = true;
            }
        }
        offset = offset.saturating_add(command_size as usize);
        if offset as u64 > commands_end {
            return false;
        }
    }
    offset as u64 == commands_end && executable_segment
}

fn validate_arm64_kernel(component: &ComponentSource) -> Result<(), StageRuntimeError> {
    let bytes = read_prefix(component, 64)?;
    let file_size = file_size(component)?;
    let image_size = bytes
        .get(16..24)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes);
    if bytes.get(56..60) == Some(b"ARM\x64")
        && image_size.is_some_and(|size| size >= 64 && size <= file_size)
    {
        return Ok(());
    }
    invalid_architecture(component, Architecture::Arm64, "Linux Image")
}

fn validate_initramfs(
    component: &ComponentSource,
    expected: Architecture,
) -> Result<(), StageRuntimeError> {
    let file = fs::File::open(&component.source).map_err(|source| StageRuntimeError::Io {
        operation: "open",
        path: component.source.clone(),
        source,
    })?;
    let mut decoder = GzDecoder::new(file);
    loop {
        let mut reader =
            cpio::NewcReader::new(decoder).map_err(|source| invalid_archive(component, source))?;
        if reader.entry().is_trailer() {
            return Err(StageRuntimeError::InvalidComponent {
                component: component.name,
                path: component.source.clone(),
                reason: "archive has no init entry".to_string(),
            });
        }
        let is_init = reader.entry().name() == "init";
        if is_init {
            let mode = reader.entry().mode();
            if mode & 0o170000 != 0o100000 || mode & 0o111 == 0 {
                return Err(StageRuntimeError::InvalidComponent {
                    component: component.name,
                    path: component.source.clone(),
                    reason: "init entry must be a regular executable file".to_string(),
                });
            }
            if u64::from(reader.entry().file_size()) > MAX_INIT_SIZE {
                return Err(StageRuntimeError::InvalidComponent {
                    component: component.name,
                    path: component.source.clone(),
                    reason: format!("init entry exceeds {MAX_INIT_SIZE} bytes"),
                });
            }
            let mut contents = Vec::new();
            reader
                .read_to_end(&mut contents)
                .map_err(|source| invalid_archive(component, source))?;
            let source =
                ComponentSource::readable("initramfs init", component.source.clone(), "init");
            return validate_elf_bytes(&source, &contents, expected);
        }
        decoder = reader
            .finish()
            .map_err(|source| invalid_archive(component, source))?;
    }
}

fn validate_elf_bytes(
    component: &ComponentSource,
    bytes: &[u8],
    expected: Architecture,
) -> Result<(), StageRuntimeError> {
    if valid_elf_header(bytes, bytes.len() as u64, expected) {
        return Ok(());
    }
    invalid_architecture(component, expected, "ELF")
}

fn valid_elf_header(bytes: &[u8], file_size: u64, expected: Architecture) -> bool {
    if bytes.len() < 64
        || bytes.get(..4) != Some(b"\x7fELF")
        || bytes.get(4) != Some(&2)
        || bytes.get(5) != Some(&1)
        || bytes.get(6) != Some(&1)
    {
        return false;
    }
    let expected_machine = match expected {
        Architecture::X86_64 => 62,
        Architecture::Arm64 => 183,
    };
    let elf_type = read_u16_le(bytes, 16);
    let machine = read_u16_le(bytes, 18);
    let version = read_u32_le(bytes, 20);
    let program_offset = read_u64_le(bytes, 32);
    let header_size = read_u16_le(bytes, 52);
    let program_entry_size = read_u16_le(bytes, 54);
    let program_count = read_u16_le(bytes, 56);
    let (Some(program_offset), Some(program_entry_size), Some(program_count)) =
        (program_offset, program_entry_size, program_count)
    else {
        return false;
    };
    let program_end = program_offset
        .saturating_add(u64::from(program_entry_size).saturating_mul(u64::from(program_count)));
    matches!(elf_type, Some(2) | Some(3))
        && machine == Some(expected_machine)
        && version == Some(1)
        && header_size == Some(64)
        && program_offset >= 64
        && program_entry_size >= 56
        && program_count > 0
        && program_end <= file_size
        && program_end <= bytes.len() as u64
        && has_executable_load_segment(
            bytes,
            program_offset as usize,
            program_entry_size as usize,
            program_count as usize,
            file_size,
        )
}

fn has_executable_load_segment(
    bytes: &[u8],
    program_offset: usize,
    entry_size: usize,
    entry_count: usize,
    file_size: u64,
) -> bool {
    (0..entry_count).any(|index| {
        let offset = program_offset.saturating_add(index.saturating_mul(entry_size));
        let segment_type = read_u32_le(bytes, offset);
        let flags = read_u32_le(bytes, offset + 4);
        let file_offset = read_u64_le(bytes, offset + 8);
        let file_length = read_u64_le(bytes, offset + 32);
        let memory_length = read_u64_le(bytes, offset + 40);
        segment_type == Some(1)
            && flags.is_some_and(|value| value & 0x1 != 0)
            && file_offset.zip(file_length).zip(memory_length).is_some_and(
                |((start, length), memory)| {
                    length > 0 && length <= memory && start.saturating_add(length) <= file_size
                },
            )
    })
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.saturating_add(2))?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.saturating_add(4))?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.saturating_add(8))?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn file_size(component: &ComponentSource) -> Result<u64, StageRuntimeError> {
    fs::metadata(&component.source)
        .map(|metadata| metadata.len())
        .map_err(|source| StageRuntimeError::Io {
            operation: "inspect",
            path: component.source.clone(),
            source,
        })
}

fn invalid_archive(component: &ComponentSource, source: io::Error) -> StageRuntimeError {
    StageRuntimeError::InvalidComponent {
        component: component.name,
        path: component.source.clone(),
        reason: format!("invalid gzip newc archive: {source}"),
    }
}

fn invalid_architecture<T>(
    component: &ComponentSource,
    expected: Architecture,
    format: &str,
) -> Result<T, StageRuntimeError> {
    Err(StageRuntimeError::InvalidComponent {
        component: component.name,
        path: component.source.clone(),
        reason: format!("expected {expected:?} {format}"),
    })
}

fn read_prefix(component: &ComponentSource, length: usize) -> Result<Vec<u8>, StageRuntimeError> {
    let mut file = fs::File::open(&component.source).map_err(|source| StageRuntimeError::Io {
        operation: "open",
        path: component.source.clone(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(length);
    file.by_ref()
        .take(length as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| StageRuntimeError::Io {
            operation: "read",
            path: component.source.clone(),
            source,
        })?;
    Ok(bytes)
}

fn temporary_stage_dir(stage_dir: &Path) -> Result<PathBuf, StageRuntimeError> {
    let parent = stage_dir
        .parent()
        .ok_or_else(|| StageRuntimeError::InvalidComponent {
            component: "stage directory",
            path: stage_dir.to_path_buf(),
            reason: "path has no parent".to_string(),
        })?;
    fs::create_dir_all(parent).map_err(|source| StageRuntimeError::Io {
        operation: "create stage parent directory",
        path: parent.to_path_buf(),
        source,
    })?;
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(".stage-{}-{attempt}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(StageRuntimeError::Io {
                    operation: "create temporary stage directory",
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(StageRuntimeError::InvalidComponent {
        component: "stage directory",
        path: parent.to_path_buf(),
        reason: "could not allocate a temporary directory".to_string(),
    })
}

fn create_directory(path: &Path) -> Result<(), StageRuntimeError> {
    fs::create_dir_all(path).map_err(|source| StageRuntimeError::Io {
        operation: "create directory",
        path: path.to_path_buf(),
        source,
    })?;
    set_mode(path, EXECUTABLE_MODE)
}

fn copy_file(component: &ComponentSource, destination: &Path) -> Result<(), StageRuntimeError> {
    fs::copy(&component.source, destination).map_err(|source| StageRuntimeError::Io {
        operation: "copy component to",
        path: destination.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), StageRuntimeError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        StageRuntimeError::Io {
            operation: "set permissions on",
            path: path.to_path_buf(),
            source,
        }
    })
}

fn validate_staged_tree(root: &Path) -> Result<(), StageRuntimeError> {
    let expected = [
        "assets/agent",
        "assets/initramfs",
        "assets/kernel-default",
        "bin/krun",
        "bin/netd",
        "bin/vmmon",
    ];
    let mut actual = Vec::new();
    for directory in ["assets", "bin"] {
        let path = root.join(directory);
        for entry in fs::read_dir(&path).map_err(|source| StageRuntimeError::Io {
            operation: "read directory",
            path: path.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| StageRuntimeError::Io {
                operation: "read directory entry in",
                path: path.clone(),
                source,
            })?;
            if !entry
                .file_type()
                .map_err(|source| StageRuntimeError::Io {
                    operation: "inspect",
                    path: entry.path(),
                    source,
                })?
                .is_file()
            {
                return Err(StageRuntimeError::InvalidComponent {
                    component: "staged payload",
                    path: entry.path(),
                    reason: "entry is not a regular file".to_string(),
                });
            }
            actual.push(format!(
                "{directory}/{}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    actual.sort();
    if actual == expected {
        return Ok(());
    }
    Err(StageRuntimeError::InvalidComponent {
        component: "staged payload",
        path: root.to_path_buf(),
        reason: format!("expected {expected:?}, found {actual:?}"),
    })
}

fn replace_stage_directory(temporary: &Path, destination: &Path) -> Result<(), StageRuntimeError> {
    let existing = match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_dir() => true,
        Ok(_) => {
            return Err(StageRuntimeError::InvalidComponent {
                component: "stage directory",
                path: destination.to_path_buf(),
                reason: "destination is not a real directory".to_string(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(StageRuntimeError::Io {
                operation: "inspect stage directory",
                path: destination.to_path_buf(),
                source,
            });
        }
    };
    if !existing {
        return fs::rename(temporary, destination).map_err(|source| StageRuntimeError::Io {
            operation: "install stage directory",
            path: destination.to_path_buf(),
            source,
        });
    }

    let backup = unused_sibling_path(destination, "previous")?;
    fs::rename(destination, &backup).map_err(|source| StageRuntimeError::Io {
        operation: "preserve existing stage directory",
        path: destination.to_path_buf(),
        source,
    })?;
    if let Err(source) = fs::rename(temporary, destination) {
        let restore = fs::rename(&backup, destination);
        return match restore {
            Ok(()) => Err(StageRuntimeError::Io {
                operation: "install stage directory",
                path: destination.to_path_buf(),
                source,
            }),
            Err(restore_error) => Err(StageRuntimeError::InvalidComponent {
                component: "stage directory",
                path: destination.to_path_buf(),
                reason: format!(
                    "install failed: {source}; restoring previous stage from {} also failed: {restore_error}",
                    backup.display()
                ),
            }),
        };
    }
    fs::remove_dir_all(&backup).map_err(|source| StageRuntimeError::Io {
        operation: "remove previous stage directory",
        path: backup,
        source,
    })
}

fn unused_sibling_path(path: &Path, label: &str) -> Result<PathBuf, StageRuntimeError> {
    let parent = path
        .parent()
        .ok_or_else(|| StageRuntimeError::InvalidComponent {
            component: "stage directory",
            path: path.to_path_buf(),
            reason: "path has no parent".to_string(),
        })?;
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(".{label}-{}-{attempt}", std::process::id()));
        if fs::symlink_metadata(&candidate)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        {
            return Ok(candidate);
        }
    }
    Err(StageRuntimeError::InvalidComponent {
        component: "stage directory",
        path: parent.to_path_buf(),
        reason: format!("could not allocate a {label} directory name"),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use crate::initramfs::{write_initramfs, InitramfsOptions};
    use crate::release_target::{BuildProfile, ReleaseTarget};
    use crate::stage_runtime::{
        architecture_for_guest_target, replace_stage_directory, stage_runtime_for_host,
        Architecture, StageRuntimeError, StageRuntimeOptions, EXECUTABLE_MODE, READABLE_MODE,
    };

    #[test]
    fn stages_each_release_target_with_exact_paths_and_modes() {
        for target in [
            ReleaseTarget::DarwinArm64,
            ReleaseTarget::LinuxAmd64Gnu,
            ReleaseTarget::LinuxArm64Gnu,
        ] {
            let fixture = Fixture::new(target);
            let staged = stage_runtime_for_host(&fixture.options(), target).expect("stage runtime");

            assert_eq!(staged, fixture.expected_stage_dir());
            for relative in ["bin/vmmon", "bin/netd", "bin/krun", "assets/agent"] {
                assert_eq!(mode(&staged.join(relative)), EXECUTABLE_MODE);
            }
            for relative in ["assets/kernel-default", "assets/initramfs"] {
                assert_eq!(mode(&staged.join(relative)), READABLE_MODE);
            }
            assert!(!staged.join("init").exists());
            assert!(!staged.join("silo").exists());
        }
    }

    #[test]
    fn rejects_missing_component_without_replacing_existing_stage() {
        let fixture = Fixture::new(ReleaseTarget::LinuxArm64Gnu);
        let stage = fixture.expected_stage_dir();
        fs::create_dir_all(&stage).expect("create existing stage");
        fs::write(stage.join("keep"), b"old").expect("write existing stage");
        fs::remove_file(fixture.target_dir.join("release/netd")).expect("remove netd");

        let error = stage_runtime_for_host(&fixture.options(), fixture.target)
            .expect_err("missing netd must fail");

        assert!(matches!(
            error,
            StageRuntimeError::InvalidComponent {
                component: "netd",
                ..
            }
        ));
        assert!(stage.join("keep").is_file());
    }

    #[test]
    fn rejects_non_native_release_target() {
        let fixture = Fixture::new(ReleaseTarget::LinuxArm64Gnu);

        let error = stage_runtime_for_host(&fixture.options(), ReleaseTarget::LinuxAmd64Gnu)
            .expect_err("cross-target staging must fail");

        assert!(matches!(
            error,
            StageRuntimeError::HostTargetMismatch { .. }
        ));
    }

    #[test]
    fn rejects_symlinked_and_truncated_sources() {
        let fixture = Fixture::new(ReleaseTarget::LinuxAmd64Gnu);
        let netd = fixture.target_dir.join("release/netd");
        fs::remove_file(&netd).expect("remove netd");
        std::os::unix::fs::symlink(fixture.target_dir.join("release/vmmon"), &netd)
            .expect("symlink netd");
        assert!(matches!(
            stage_runtime_for_host(&fixture.options(), fixture.target),
            Err(StageRuntimeError::InvalidComponent {
                component: "netd",
                ..
            })
        ));

        fs::remove_file(&netd).expect("remove symlink");
        write_source(&netd, b"\x7fELF\x02\x01\x01");
        assert!(matches!(
            stage_runtime_for_host(&fixture.options(), fixture.target),
            Err(StageRuntimeError::InvalidComponent {
                component: "netd",
                ..
            })
        ));
    }

    #[test]
    fn rejects_wrong_helper_agent_kernel_and_initramfs_architectures() {
        for component in ["vmmon", "agent", "kernel", "initramfs"] {
            let fixture = Fixture::new(ReleaseTarget::LinuxArm64Gnu);
            match component {
                "vmmon" => write_elf(
                    &fixture.target_dir.join("release/vmmon"),
                    Architecture::X86_64,
                ),
                "agent" => write_elf(
                    &fixture.target_dir.join("resources/assets/agent"),
                    Architecture::X86_64,
                ),
                "kernel" => write_elf(&fixture.kernel, Architecture::X86_64),
                "initramfs" => write_initramfs_fixture(
                    &fixture.target_dir.join("resources/assets/initramfs"),
                    Architecture::X86_64,
                ),
                _ => unreachable!(),
            }

            let error = stage_runtime_for_host(&fixture.options(), fixture.target)
                .expect_err("wrong architecture must fail");
            assert!(matches!(
                error,
                StageRuntimeError::InvalidComponent { component: actual, .. }
                    if actual == component || (component == "initramfs" && actual == "initramfs init")
            ));
        }
    }

    #[test]
    fn restaging_removes_stale_files() {
        let fixture = Fixture::new(ReleaseTarget::LinuxAmd64Gnu);
        let stage =
            stage_runtime_for_host(&fixture.options(), fixture.target).expect("first stage");
        fs::write(stage.join("stale"), b"stale").expect("write stale file");

        stage_runtime_for_host(&fixture.options(), fixture.target).expect("replace stage");

        assert!(!stage.join("stale").exists());
        assert!(stage.join("bin/vmmon").is_file());
    }

    #[test]
    fn failed_install_restores_previous_stage() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("stage");
        fs::create_dir(&destination).expect("create previous stage");
        fs::write(destination.join("keep"), b"old").expect("write previous stage");

        let error = replace_stage_directory(&temp.path().join("missing"), &destination)
            .expect_err("install should fail");

        assert!(matches!(error, StageRuntimeError::Io { .. }));
        assert_eq!(
            fs::read(destination.join("keep")).expect("read restored stage"),
            b"old"
        );
    }

    #[test]
    fn kernel_path_must_be_absolute() {
        let fixture = Fixture::new(ReleaseTarget::LinuxAmd64Gnu);
        let mut options = fixture.options();
        options.kernel = PathBuf::from("vmlinux");

        assert!(matches!(
            stage_runtime_for_host(&options, fixture.target),
            Err(StageRuntimeError::RelativeKernel { .. })
        ));
    }

    struct Fixture {
        _temp: tempfile::TempDir,
        target: ReleaseTarget,
        target_dir: PathBuf,
        kernel: PathBuf,
    }

    impl Fixture {
        fn new(target: ReleaseTarget) -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let target_dir = temp.path().join("target");
            let profile = target_dir.join("release");
            let assets = target_dir.join("resources/assets");
            fs::create_dir_all(&profile).expect("create profile");
            fs::create_dir_all(&assets).expect("create assets");
            let architecture = architecture_for_guest_target(target.descriptor().guest_target);
            for helper in ["vmmon", "netd", "krun"] {
                let path = profile.join(helper);
                if target == ReleaseTarget::DarwinArm64 {
                    write_macho(&path);
                } else {
                    write_elf(&path, architecture);
                }
            }
            write_elf(&assets.join("agent"), architecture);
            write_initramfs_fixture(&assets.join("initramfs"), architecture);
            let kernel = temp.path().join("kernel");
            if architecture == Architecture::Arm64 {
                write_arm64_kernel(&kernel);
            } else {
                write_elf(&kernel, architecture);
            }
            Self {
                _temp: temp,
                target,
                target_dir,
                kernel,
            }
        }

        fn options(&self) -> StageRuntimeOptions {
            StageRuntimeOptions {
                target: self.target,
                profile: BuildProfile::Release,
                kernel: self.kernel.clone(),
                target_dir: self.target_dir.clone(),
            }
        }

        fn expected_stage_dir(&self) -> PathBuf {
            self.target
                .descriptor()
                .stage_dir_in(&self.target_dir, BuildProfile::Release)
        }
    }

    fn write_elf(path: &Path, architecture: Architecture) {
        let mut bytes = vec![0_u8; 120];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(
            &match architecture {
                Architecture::X86_64 => 62_u16,
                Architecture::Arm64 => 183_u16,
            }
            .to_le_bytes(),
        );
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&120_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&120_u64.to_le_bytes());
        write_source(path, &bytes);
    }

    fn write_macho(path: &Path) {
        let mut bytes = vec![0_u8; 104];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&72_u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x19_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&72_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&104_u64.to_le_bytes());
        bytes[92..96].copy_from_slice(&5_u32.to_le_bytes());
        write_source(path, &bytes);
    }

    fn write_arm64_kernel(path: &Path) {
        let mut bytes = vec![0_u8; 64];
        bytes[16..24].copy_from_slice(&64_u64.to_le_bytes());
        bytes[56..60].copy_from_slice(b"ARM\x64");
        write_source(path, &bytes);
    }

    fn write_initramfs_fixture(path: &Path, architecture: Architecture) {
        let init = path.with_extension("init");
        write_elf(&init, architecture);
        write_initramfs(&InitramfsOptions::new(&init, path)).expect("write initramfs");
        fs::remove_file(init).expect("remove init source");
    }

    fn write_source(path: &Path, contents: &[u8]) {
        fs::create_dir_all(path.parent().expect("source parent")).expect("create source parent");
        fs::write(path, contents).expect("write source");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set source mode");
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }
}

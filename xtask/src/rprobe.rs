use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::initramfs::{write_initramfs, InitramfsError, InitramfsOptions};

const ELF_HEADER_LEN: usize = 64;
const ELF_PROGRAM_HEADER_LEN: usize = 56;
const ELF_MACHINE_AARCH64: u16 = 183;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_PROGRAM_LOAD: u32 = 1;
const ELF_PROGRAM_DYNAMIC: u32 = 2;
const ELF_PROGRAM_INTERPRETER: u32 = 3;
const ELF_PROGRAM_EXECUTABLE: u32 = 1;

pub const ASSETS: [(&str, u32); 1] = [("rprobe", 0o644)];

pub fn installed_asset_set_present(assets: &Path) -> io::Result<bool> {
    entry_present(&assets.join("rprobe"))
}

fn entry_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Error)]
pub enum RprobeError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Initramfs(#[from] InitramfsError),
    #[error("failed to read rprobe artifact {path}")]
    Read { path: PathBuf, source: io::Error },
    #[error("invalid rprobe ELF {path}: {reason}")]
    InvalidElf { path: PathBuf, reason: &'static str },
    #[error("rprobe initramfs reproducibility check failed")]
    NonDeterministicArchive,
    #[error("failed to remove temporary archive {path}")]
    RemoveTemporary { path: PathBuf, source: io::Error },
    #[error("failed to publish rprobe artifact {path}")]
    Publish { path: PathBuf, source: io::Error },
}

pub type Result<T> = std::result::Result<T, RprobeError>;

pub fn package(binary: &Path, output: &Path) -> Result<()> {
    let binary_identity = validate_elf(binary)?;
    let first = temporary_archive(output, "first");
    let second = temporary_archive(output, "second");
    write_initramfs(&InitramfsOptions::rprobe(binary, &first))?;
    write_initramfs(&InitramfsOptions::rprobe(binary, &second))?;
    let archive_identity = file_identity(&first)?;
    let verification_identity = file_identity(&second)?;
    fs::remove_file(&second).map_err(|source| RprobeError::RemoveTemporary {
        path: second,
        source,
    })?;
    if archive_identity != verification_identity {
        let _ = fs::remove_file(first);
        return Err(RprobeError::NonDeterministicArchive);
    }
    fs::rename(&first, output).map_err(|source| RprobeError::Publish {
        path: output.to_path_buf(),
        source,
    })?;

    println!(
        "rprobe_binary_size={} rprobe_binary_sha256={} initramfs_size={} initramfs_sha256={}",
        binary_identity.size,
        binary_identity.sha256,
        archive_identity.size,
        archive_identity.sha256
    );
    Ok(())
}

pub fn build_kernel(workspace: &Path, binary: &Path, build: &Path, assets: &Path) -> Result<()> {
    for directory in [build, assets] {
        fs::create_dir_all(directory).map_err(|source| RprobeError::Publish {
            path: directory.to_path_buf(),
            source,
        })?;
    }
    let archive = build.join("initramfs.cpio.gz");
    package(binary, &archive)?;
    let mut make = Command::new("make");
    make.current_dir(workspace.join("resources/kernels"))
        .args(["kernel-image", "KERNEL_PROFILE=rprobe"])
        .arg(format!("KERNEL_INITRAMFS={}", archive.display()))
        .arg(format!(
            "KERNEL_IMAGE_OUTPUT={}",
            assets.join("rprobe").display()
        ));
    command::run(make)?;
    Ok(())
}

fn temporary_archive(output: &Path, label: &str) -> PathBuf {
    output.with_extension(format!("rprobe-{label}-{}", std::process::id()))
}

pub fn run_hardware_test(workspace_root: &Path, target_dir: &Path, kernel: &Path) -> Result<()> {
    let mut cargo = Command::new("cargo");
    cargo
        .current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", target_dir)
        .args([
            "build",
            "--locked",
            "-p",
            "silo-vmm",
            "--bin",
            "silo-rprobe-vz-harness",
        ]);
    command::run(cargo)?;

    let harness = target_dir.join("debug/silo-rprobe-vz-harness");
    let entitlements = workspace_root.join("virt/vmm/silo-vmm.entitlements");
    let mut sign = Command::new("/usr/bin/codesign");
    sign.args(["-f", "--entitlements"])
        .arg(entitlements)
        .args(["-s", "-"])
        .arg(&harness);
    command::run(sign)?;

    let mut verify = Command::new("/usr/bin/codesign");
    verify.args(["--verify", "--verbose=4"]).arg(&harness);
    command::run(verify)?;

    let mut run = Command::new(harness);
    run.args(["--kernel"]).arg(kernel);
    command::run(run)?;

    let harness = target_dir.join("debug/silo-rprobe-vz-harness");
    let mut cancel_starting = Command::new(harness);
    cancel_starting.args(["--kernel"]).arg(kernel);
    cancel_starting.arg("--cancel-while-starting");
    command::run(cancel_starting)?;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct FileIdentity {
    size: u64,
    sha256: String,
}

fn validate_elf(path: &Path) -> Result<FileIdentity> {
    let bytes = fs::read(path).map_err(|source| RprobeError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    validate_elf_bytes(path, &bytes)?;
    Ok(FileIdentity {
        size: bytes.len() as u64,
        sha256: digest_hex(&Sha256::digest(&bytes)),
    })
}

fn validate_elf_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let invalid = |reason| RprobeError::InvalidElf {
        path: path.to_path_buf(),
        reason,
    };
    if bytes.len() < ELF_HEADER_LEN || &bytes[..4] != b"\x7fELF" {
        return Err(invalid("missing ELF64 header"));
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(invalid("ELF must be 64-bit little-endian version 1"));
    }
    if read_u16(bytes, 16).ok_or_else(|| invalid("truncated ELF type"))? != ELF_TYPE_EXECUTABLE {
        return Err(invalid("ELF must be an executable"));
    }
    if read_u16(bytes, 18).ok_or_else(|| invalid("truncated ELF machine"))? != ELF_MACHINE_AARCH64 {
        return Err(invalid("ELF machine is not AArch64"));
    }
    let entry = read_u64(bytes, 24).ok_or_else(|| invalid("truncated ELF entry point"))?;
    if entry == 0 {
        return Err(invalid("ELF entry point is zero"));
    }

    let program_offset = usize::try_from(
        read_u64(bytes, 32).ok_or_else(|| invalid("truncated program header offset"))?,
    )
    .map_err(|_| invalid("program header offset is too large"))?;
    let entry_size =
        usize::from(read_u16(bytes, 54).ok_or_else(|| invalid("truncated program header size"))?);
    let entry_count =
        usize::from(read_u16(bytes, 56).ok_or_else(|| invalid("truncated program header count"))?);
    if entry_size < ELF_PROGRAM_HEADER_LEN || entry_count == 0 {
        return Err(invalid("invalid program header table"));
    }
    let table_size = entry_size
        .checked_mul(entry_count)
        .ok_or_else(|| invalid("program header table overflows"))?;
    let table_end = program_offset
        .checked_add(table_size)
        .ok_or_else(|| invalid("program header table overflows"))?;
    if table_end > bytes.len() {
        return Err(invalid("truncated program header table"));
    }
    let mut has_load = false;
    let mut entry_is_executable = false;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| invalid("program header offset overflows"))?,
            )
            .ok_or_else(|| invalid("program header offset overflows"))?;
        let program_type =
            read_u32(bytes, offset).ok_or_else(|| invalid("truncated program header"))?;
        match program_type {
            ELF_PROGRAM_INTERPRETER => return Err(invalid("PT_INTERP is forbidden")),
            ELF_PROGRAM_DYNAMIC => return Err(invalid("PT_DYNAMIC is forbidden")),
            _ => {}
        }
        if program_type != ELF_PROGRAM_LOAD {
            continue;
        }

        has_load = true;
        let flags =
            read_u32(bytes, offset + 4).ok_or_else(|| invalid("truncated PT_LOAD flags"))?;
        let file_offset = usize::try_from(
            read_u64(bytes, offset + 8).ok_or_else(|| invalid("truncated PT_LOAD file offset"))?,
        )
        .map_err(|_| invalid("PT_LOAD file offset is too large"))?;
        let virtual_address = read_u64(bytes, offset + 16)
            .ok_or_else(|| invalid("truncated PT_LOAD virtual address"))?;
        let file_size = usize::try_from(
            read_u64(bytes, offset + 32).ok_or_else(|| invalid("truncated PT_LOAD file size"))?,
        )
        .map_err(|_| invalid("PT_LOAD file size is too large"))?;
        let memory_size =
            read_u64(bytes, offset + 40).ok_or_else(|| invalid("truncated PT_LOAD memory size"))?;
        if u64::try_from(file_size).map_err(|_| invalid("PT_LOAD file size is too large"))?
            > memory_size
        {
            return Err(invalid("PT_LOAD file size exceeds memory size"));
        }
        let file_end = file_offset
            .checked_add(file_size)
            .ok_or_else(|| invalid("PT_LOAD file range overflows"))?;
        if file_end > bytes.len() {
            return Err(invalid("PT_LOAD file range exceeds the ELF"));
        }
        let memory_end = virtual_address
            .checked_add(memory_size)
            .ok_or_else(|| invalid("PT_LOAD memory range overflows"))?;
        if flags & ELF_PROGRAM_EXECUTABLE != 0
            && memory_size != 0
            && entry >= virtual_address
            && entry < memory_end
        {
            entry_is_executable = true;
        }
    }
    if !has_load {
        return Err(invalid("ELF has no PT_LOAD segment"));
    }
    if !entry_is_executable {
        return Err(invalid(
            "ELF entry point is outside executable PT_LOAD segments",
        ));
    }

    Ok(())
}

fn file_identity(path: &Path) -> Result<FileIdentity> {
    let file = File::open(path).map_err(|source| RprobeError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let size = file
        .metadata()
        .map_err(|source| RprobeError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    let mut reader = io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| RprobeError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(FileIdentity {
        size,
        sha256: digest_hex(&hasher.finalize()),
    })
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::rprobe::{read_u16, read_u32, read_u64, validate_elf_bytes};

    #[test]
    fn installed_probe_is_a_single_asset_without_a_sidecar() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rprobe-assets-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        assert!(!crate::rprobe::installed_asset_set_present(&directory).unwrap());
        std::fs::write(directory.join("rprobe"), b"kernel").unwrap();
        assert!(crate::rprobe::installed_asset_set_present(&directory).unwrap());
        assert_eq!(crate::rprobe::ASSETS, [("rprobe", 0o644)]);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn little_endian_elf_fields_are_read_without_native_layout() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(read_u16(&bytes, 1), Some(0x0302));
        assert_eq!(read_u32(&bytes, 2), Some(0x0605_0403));
        assert_eq!(read_u64(&bytes, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(read_u64(&bytes, 1), None);
    }

    #[test]
    fn validates_minimal_static_aarch64_executable() {
        assert!(validate_elf_bytes(Path::new("fixture"), &elf()).is_ok());

        let mut wrong_machine = elf();
        wrong_machine[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &wrong_machine).is_err());
    }

    #[test]
    fn rejects_forbidden_or_non_loadable_program_headers() {
        let mut dynamic = elf();
        dynamic[64..68].copy_from_slice(&2u32.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &dynamic).is_err());

        let mut interpreter = elf();
        interpreter[64..68].copy_from_slice(&3u32.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &interpreter).is_err());

        let mut no_load = elf();
        no_load[64..68].copy_from_slice(&4u32.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &no_load).is_err());

        let mut non_executable = elf();
        non_executable[68..72].copy_from_slice(&4u32.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &non_executable).is_err());

        let mut entry_outside = elf();
        entry_outside[24..32].copy_from_slice(&0x50_0000u64.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &entry_outside).is_err());
    }

    #[test]
    fn rejects_overflowing_or_invalid_load_ranges() {
        let mut memory_overflow = elf();
        memory_overflow[80..88].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        memory_overflow[104..112].copy_from_slice(&4u64.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &memory_overflow).is_err());

        let mut file_overflow = elf();
        file_overflow[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &file_overflow).is_err());

        let mut file_past_end = elf();
        file_past_end[96..104].copy_from_slice(&2u64.to_le_bytes());
        file_past_end[104..112].copy_from_slice(&2u64.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &file_past_end).is_err());

        let mut file_larger_than_memory = elf();
        file_larger_than_memory[96..104].copy_from_slice(&2u64.to_le_bytes());
        assert!(validate_elf_bytes(Path::new("fixture"), &file_larger_than_memory).is_err());
    }

    fn elf() -> Vec<u8> {
        let mut bytes = vec![0u8; 121];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x40_0000u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&1u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1u64.to_le_bytes());
        bytes[120] = 0xd6;
        bytes
    }
}

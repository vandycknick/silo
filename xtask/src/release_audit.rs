use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use cpio::NewcReader;
use flate2::read::GzDecoder;
use thiserror::Error;

use crate::command;
use crate::components::BuildContext;
use crate::profiles::Profile;
use crate::runtime;
use crate::targets::HostTarget;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Runtime(#[from] runtime::RuntimeError),
    #[error("release audit failed for {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
    #[error("failed to read release artifact {path}")]
    ReadArtifact {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn verify(
    workspace_root: &Path,
    target_dir: &Path,
    profile: Profile,
) -> Result<(), AuditError> {
    if profile != Profile::Release {
        return invalid(
            target_dir,
            "verify-runtime only audits release outputs".to_string(),
        );
    }
    let host = HostTarget::current().map_err(|error| AuditError::Invalid {
        path: target_dir.to_path_buf(),
        reason: error.to_string(),
    })?;
    let release = target_dir.join("release");
    let stage = target_dir
        .join("silo-runtime")
        .join(host.runtime_target())
        .join("release");
    let host_binaries = [
        ("silo", release.join("silo")),
        ("vmmon", release.join("vmmon")),
        ("netd", release.join("netd")),
        ("krun", release.join("krun")),
    ];
    match host {
        HostTarget::MacosArm64 => {
            for (name, path) in host_binaries {
                audit_macho(name, &path)?;
            }
        }
        HostTarget::LinuxX86_64 | HostTarget::LinuxArm64 => {
            for (name, path) in host_binaries {
                audit_elf(name, &path, host)?;
            }
        }
    }
    audit_static_elf(&stage.join("assets/agent"), host)?;
    audit_staged_initramfs(&stage.join("assets/initramfs"), host, target_dir)?;
    runtime::validate_stage_against_adjacent(
        &BuildContext {
            workspace_root,
            target_dir,
            profile,
            host,
        },
        &stage,
    )?;
    Ok(())
}

pub fn verify_archive_runtime(
    root: &Path,
    portable: bool,
    host: HostTarget,
) -> Result<(), AuditError> {
    let mut binaries = vec!["vmmon", "netd", "krun"];
    if portable {
        binaries.push("silo");
    }
    match host {
        HostTarget::MacosArm64 => {
            for name in binaries {
                audit_macho(name, &root.join("bin").join(name))?;
            }
        }
        HostTarget::LinuxX86_64 | HostTarget::LinuxArm64 => {
            for name in binaries {
                audit_elf(name, &root.join("bin").join(name), host)?;
            }
        }
    }
    audit_static_elf(&root.join("assets/agent"), host)?;
    audit_extracted_initramfs(&root.join("assets/initramfs"), host)
}

pub fn audit_macho(_name: &str, path: &Path) -> Result<(), AuditError> {
    let load_commands = output("/usr/bin/otool", ["-l"], path)?;
    if load_commands.contains("LC_RPATH") {
        return invalid(path, "contains LC_RPATH".to_string());
    }
    for command in [
        "LC_LOAD_WEAK_DYLIB",
        "LC_REEXPORT_DYLIB",
        "LC_LOAD_UPWARD_DYLIB",
    ] {
        if load_commands.contains(command) {
            return invalid(path, format!("contains unsupported {command}"));
        }
    }
    let headers = output("/usr/bin/otool", ["-hv"], path)?;
    if !headers.contains("ARM64") {
        return invalid(path, "is not an arm64 Mach-O binary".to_string());
    }
    let build = output("/usr/bin/vtool", ["-show-build", "-arch", "arm64"], path)?;
    if !build.contains("platform MACOS") || !build.contains("minos 26.0") {
        return invalid(path, format!("build version is not macOS 26.0: {build}"));
    }
    let dependencies = output("/usr/bin/otool", ["-L"], path)?;
    let actual = dependencies
        .lines()
        .skip(1)
        .map(|line| {
            line.trim()
                .split_once(" (")
                .map(|(path, _)| path.to_string())
                .ok_or_else(|| AuditError::Invalid {
                    path: path.to_path_buf(),
                    reason: format!("cannot parse otool dependency line {line:?}"),
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual.iter().any(|dependency| {
        !dependency.starts_with("/System/Library/") && !dependency.starts_with("/usr/lib/")
    }) {
        return invalid(path, format!("contains a non-system dylib: {actual:?}"));
    }
    Ok(())
}

fn audit_elf(name: &str, path: &Path, host: HostTarget) -> Result<(), AuditError> {
    assert_elf_machine(path, host_machine(host))?;
    let program_headers = output("/usr/bin/readelf", ["-lW"], path)?;
    let dynamic = output("/usr/bin/readelf", ["-dW"], path)?;
    let versions = output("/usr/bin/readelf", ["--version-info"], path)?;
    if dynamic.contains("RPATH") || dynamic.contains("RUNPATH") {
        return invalid(path, "contains DT_RPATH or DT_RUNPATH".to_string());
    }
    let interpreter = elf_interpreter(&program_headers);
    if name == "netd" {
        if interpreter.is_some() {
            return invalid(path, "netd must not have a dynamic interpreter".to_string());
        }
    } else if interpreter.as_deref() != Some(expected_interpreter(host)) {
        return invalid(
            path,
            format!(
                "interpreter is {interpreter:?}, expected {}",
                expected_interpreter(host)
            ),
        );
    }
    let needed = elf_needed(&dynamic);
    let expected = elf_dependencies(name)?;
    if needed != expected {
        return invalid(
            path,
            format!("DT_NEEDED is {needed:?}, expected {expected:?}"),
        );
    }
    if needed
        .iter()
        .any(|dependency| dependency.starts_with("libkrun.so"))
    {
        return invalid(path, "depends on libkrun.so".to_string());
    }
    reject_glibc_newer_than_239(path, &versions)
}

fn audit_static_elf(path: &Path, host: HostTarget) -> Result<(), AuditError> {
    let bytes = fs::read(path).map_err(|source| AuditError::ReadArtifact {
        path: path.to_path_buf(),
        source,
    })?;
    audit_static_elf_bytes(&bytes, path, host)
}

fn audit_static_elf_bytes(bytes: &[u8], path: &Path, host: HostTarget) -> Result<(), AuditError> {
    let header = elf_header(bytes, path)?;
    let expected_machine = match host.guest_target().triple() {
        "x86_64-unknown-linux-musl" => 62,
        "aarch64-unknown-linux-musl" => 183,
        _ => return invalid(path, "unsupported guest target".to_string()),
    };
    if header.machine != expected_machine {
        return invalid(
            path,
            format!(
                "guest machine is {}, expected {expected_machine}",
                header.machine
            ),
        );
    }
    if header
        .program_types
        .iter()
        .any(|kind| matches!(kind, 2 | 3))
    {
        return invalid(path, "guest binary has PT_DYNAMIC or PT_INTERP".to_string());
    }
    Ok(())
}

fn audit_staged_initramfs(
    initramfs: &Path,
    host: HostTarget,
    target_dir: &Path,
) -> Result<(), AuditError> {
    let expected = target_dir
        .join(host.guest_target().triple())
        .join("release/init");
    audit_static_elf(&expected, host)?;
    let init = read_initramfs_init(initramfs)?;
    let expected_bytes = fs::read(&expected).map_err(|source| AuditError::ReadArtifact {
        path: expected.clone(),
        source,
    })?;
    if init != expected_bytes {
        return invalid(
            initramfs,
            "embedded init differs from the release init".to_string(),
        );
    }
    audit_static_elf_bytes(&init, initramfs, host)
}

fn audit_extracted_initramfs(initramfs: &Path, host: HostTarget) -> Result<(), AuditError> {
    let init = read_initramfs_init(initramfs)?;
    audit_static_elf_bytes(&init, initramfs, host)
}

fn read_initramfs_init(initramfs: &Path) -> Result<Vec<u8>, AuditError> {
    let file = File::open(initramfs).map_err(|source| AuditError::ReadArtifact {
        path: initramfs.to_path_buf(),
        source,
    })?;
    let mut decoder = GzDecoder::new(file);
    let expected_entries = BTreeSet::from([
        ".", "bin", "dev", "etc", "mnt", "proc", "run", "sbin", "sys", "tmp", "usr", "usr/bin",
        "usr/sbin", "init",
    ])
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    let mut entries = BTreeSet::new();
    let mut init = None;
    loop {
        let mut reader = NewcReader::new(decoder).map_err(|source| AuditError::Invalid {
            path: initramfs.to_path_buf(),
            reason: format!("cannot read gzip/newc archive: {source}"),
        })?;
        if reader.entry().is_trailer() {
            break;
        }
        let name = reader.entry().name().to_owned();
        if !entries.insert(name.clone()) || !expected_entries.contains(&name) {
            return invalid(initramfs, format!("unexpected initramfs entry {name:?}"));
        }
        let mut contents = Vec::new();
        reader
            .read_to_end(&mut contents)
            .map_err(|source| AuditError::Invalid {
                path: initramfs.to_path_buf(),
                reason: format!("cannot read initramfs entry {name:?}: {source}"),
            })?;
        if name == "init" {
            init = Some(contents);
        }
        decoder = reader.finish().map_err(|source| AuditError::Invalid {
            path: initramfs.to_path_buf(),
            reason: format!("cannot finish initramfs entry {name:?}: {source}"),
        })?;
    }
    if entries != expected_entries {
        return invalid(
            initramfs,
            format!("entries are {entries:?}, expected {expected_entries:?}"),
        );
    }
    init.ok_or_else(|| AuditError::Invalid {
        path: initramfs.to_path_buf(),
        reason: "contains no init entry".to_string(),
    })
}

fn elf_dependencies(name: &str) -> Result<BTreeSet<String>, AuditError> {
    let values: &[&str] = match name {
        "silo" | "vmmon" | "krun" => &[
            "libc.so.6",
            "libdl.so.2",
            "libgcc_s.so.1",
            "libm.so.6",
            "libpthread.so.0",
        ],
        "netd" => &[],
        _ => return invalid(Path::new(name), "no ELF allowlist".to_string()),
    };
    Ok(values.iter().map(|value| (*value).to_string()).collect())
}

fn elf_needed(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| line.split_once("Shared library: ["))
        .filter_map(|(_, value)| value.strip_suffix(']'))
        .map(str::to_string)
        .collect()
}

fn elf_interpreter(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, value) = line.split_once("Requesting program interpreter: [")?;
        value.strip_suffix(']').map(str::to_string)
    })
}

fn expected_interpreter(host: HostTarget) -> &'static str {
    match host {
        HostTarget::LinuxX86_64 => "/lib64/ld-linux-x86-64.so.2",
        HostTarget::LinuxArm64 => "/lib/ld-linux-aarch64.so.1",
        HostTarget::MacosArm64 => unreachable!("Mach-O does not have an ELF interpreter"),
    }
}

fn host_machine(host: HostTarget) -> u16 {
    match host {
        HostTarget::LinuxX86_64 => 62,
        HostTarget::LinuxArm64 | HostTarget::MacosArm64 => 183,
    }
}

fn assert_elf_machine(path: &Path, expected: u16) -> Result<(), AuditError> {
    let bytes = fs::read(path).map_err(|source| AuditError::ReadArtifact {
        path: path.to_path_buf(),
        source,
    })?;
    let header = elf_header(&bytes, path)?;
    if header.machine == expected {
        Ok(())
    } else {
        invalid(
            path,
            format!("ELF machine is {}, expected {expected}", header.machine),
        )
    }
}

struct ElfHeader {
    machine: u16,
    program_types: Vec<u32>,
}

fn elf_header(bytes: &[u8], path: &Path) -> Result<ElfHeader, AuditError> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return invalid(path, "is not a 64-bit little-endian ELF file".to_string());
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    let offset = u64::from_le_bytes(bytes[32..40].try_into().map_err(|_| AuditError::Invalid {
        path: path.to_path_buf(),
        reason: "invalid ELF program-header offset".to_string(),
    })?) as usize;
    let entry_size = usize::from(u16::from_le_bytes([bytes[54], bytes[55]]));
    let count = usize::from(u16::from_le_bytes([bytes[56], bytes[57]]));
    let Some(end) = offset.checked_add(entry_size.saturating_mul(count)) else {
        return invalid(path, "has invalid ELF program headers".to_string());
    };
    if entry_size < 4 || end > bytes.len() {
        return invalid(path, "has invalid ELF program headers".to_string());
    }
    let program_types = (0..count)
        .map(|index| {
            let start = offset + index * entry_size;
            let value = bytes
                .get(start..start + 4)
                .ok_or_else(|| AuditError::Invalid {
                    path: path.to_path_buf(),
                    reason: "has truncated ELF program headers".to_string(),
                })?;
            let value: [u8; 4] = value.try_into().map_err(|_| AuditError::Invalid {
                path: path.to_path_buf(),
                reason: "has malformed ELF program headers".to_string(),
            })?;
            Ok::<u32, AuditError>(u32::from_le_bytes(value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ElfHeader {
        machine,
        program_types,
    })
}

fn reject_glibc_newer_than_239(path: &Path, output: &str) -> Result<(), AuditError> {
    for word in output.split_whitespace() {
        let Some(version) = word.strip_prefix("GLIBC_") else {
            continue;
        };
        let mut parts = version.split('.');
        let Some(major) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(minor) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        if (major, minor) > (2, 39) {
            return invalid(path, format!("requires GLIBC_{major}.{minor}"));
        }
    }
    Ok(())
}

fn output<'a>(
    program: &str,
    args: impl IntoIterator<Item = &'a str>,
    path: &Path,
) -> Result<String, AuditError> {
    let mut command = Command::new(program);
    command.args(args).arg(path);
    output_command(command)
}

fn output_command(command: Command) -> Result<String, AuditError> {
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn invalid<T>(path: &Path, reason: String) -> Result<T, AuditError> {
    Err(AuditError::Invalid {
        path: path.to_path_buf(),
        reason,
    })
}

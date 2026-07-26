use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use cpio::NewcReader;
use flate2::read::GzDecoder;
use serde_json::json;
use thiserror::Error;

use crate::command;
use crate::profiles::Profile;
use crate::release;
use crate::targets::HostTarget;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Release(#[from] release::ReleaseError),
    #[error("release audit failed for {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
    #[error("failed to read release artifact {path}")]
    ReadArtifact {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write release provenance {path}")]
    WriteProvenance {
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
            "verify-runtime only qualifies release outputs".to_string(),
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
    let staged_binaries = [
        ("vmmon", stage.join("bin/vmmon")),
        ("netd", stage.join("bin/netd")),
        ("krun", stage.join("bin/krun")),
    ];

    match host {
        HostTarget::MacosArm64 => {
            for (name, path) in host_binaries.iter().chain(staged_binaries.iter()) {
                audit_macho(name, path, workspace_root, target_dir)?;
            }
        }
        HostTarget::LinuxX86_64 | HostTarget::LinuxArm64 => {
            for (name, path) in host_binaries.iter().chain(staged_binaries.iter()) {
                audit_elf(name, path, host, workspace_root, target_dir)?;
            }
        }
    }
    audit_static_elf(
        &stage.join("assets/agent"),
        host,
        workspace_root,
        target_dir,
    )?;
    audit_staged_initramfs(
        &stage.join("assets/initramfs"),
        host,
        workspace_root,
        target_dir,
    )?;
    verify_contaminated_binary(workspace_root, target_dir, host)?;
    write_provenance(workspace_root, target_dir, host, &release.join("netd"))
}

fn audit_macho(
    name: &str,
    path: &Path,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
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
    let expected = macho_dependencies(name)?;
    if actual != expected {
        return invalid(
            path,
            format!("dylibs are {actual:?}, expected {expected:?}"),
        );
    }
    reject_build_paths(path, workspace_root, target_dir)
}

fn macho_dependencies(name: &str) -> Result<BTreeSet<String>, AuditError> {
    let values: &[&str] = match name {
        "silo" => &[
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "/System/Library/Frameworks/Security.framework/Versions/A/Security",
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libiconv.2.dylib",
        ],
        "vmmon" => &[
            "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit",
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
            "/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization",
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libiconv.2.dylib",
            "/usr/lib/libobjc.A.dylib",
        ],
        "netd" => &[
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "/System/Library/Frameworks/Security.framework/Versions/A/Security",
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libresolv.9.dylib",
        ],
        "krun" => &[
            "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libiconv.2.dylib",
        ],
        _ => return invalid(Path::new(name), "no Mach-O allowlist".to_string()),
    };
    Ok(values.iter().map(|value| (*value).to_string()).collect())
}

fn audit_elf(
    name: &str,
    path: &Path,
    host: HostTarget,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
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
    reject_glibc_newer_than_239(path, &versions)?;
    reject_build_paths(path, workspace_root, target_dir)
}

fn audit_static_elf(
    path: &Path,
    host: HostTarget,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
    let bytes = fs::read(path).map_err(|source| AuditError::ReadArtifact {
        path: path.to_path_buf(),
        source,
    })?;
    let header = elf_header(&bytes, path)?;
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
    reject_build_paths(path, workspace_root, target_dir)
}

fn audit_staged_initramfs(
    initramfs: &Path,
    host: HostTarget,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
    let expected = target_dir
        .join("release-build")
        .join(host.runtime_target())
        .join(host.guest_target().triple())
        .join("release/init");
    audit_static_elf(&expected, host, workspace_root, target_dir)?;
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
    let expected_bytes = fs::read(&expected).map_err(|source| AuditError::ReadArtifact {
        path: expected.clone(),
        source,
    })?;
    let init = init.ok_or_else(|| AuditError::Invalid {
        path: initramfs.to_path_buf(),
        reason: "contains no init entry".to_string(),
    })?;
    if init != expected_bytes {
        return invalid(
            initramfs,
            "embedded init differs from release-build init".to_string(),
        );
    }
    let temporary = target_dir.join(format!(".release-audit-init-{}", std::process::id()));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| AuditError::WriteProvenance {
            path: temporary.clone(),
            source,
        })?;
    output
        .write_all(&init)
        .map_err(|source| AuditError::WriteProvenance {
            path: temporary.clone(),
            source,
        })?;
    drop(output);
    let result = audit_static_elf(&temporary, host, workspace_root, target_dir);
    let _ = fs::remove_file(&temporary);
    result
}

fn verify_contaminated_binary(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), AuditError> {
    let contaminated_target = target_dir.join("release-audit-contaminated");
    if contaminated_target.exists() {
        fs::remove_dir_all(&contaminated_target).map_err(|source| AuditError::WriteProvenance {
            path: contaminated_target.clone(),
            source,
        })?;
    }
    let cargo = release::tool("cargo")?;
    let rpath = "/tmp/silo-audit-contaminated";
    let mut build = Command::new(cargo);
    build
        .current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", &contaminated_target)
        .env("RUSTFLAGS", format!("-C link-arg=-Wl,-rpath,{rpath}"))
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!("-C\u{1f}link-arg=-Wl,-rpath,{rpath}"),
        )
        .args(["build", "--locked", "--release", "-p", "cli"]);
    command::run(build)?;
    let contaminated = contaminated_target.join("release/silo");
    let result = match host {
        HostTarget::MacosArm64 => audit_macho("silo", &contaminated, workspace_root, target_dir),
        HostTarget::LinuxX86_64 | HostTarget::LinuxArm64 => {
            audit_elf("silo", &contaminated, host, workspace_root, target_dir)
        }
    };
    match result {
        Err(AuditError::Invalid { reason, .. }) if reason.contains("RPATH") => Ok(()),
        Err(AuditError::Invalid { reason, .. }) => invalid(
            &contaminated,
            format!("contaminated binary failed for the wrong reason: {reason}"),
        ),
        Err(error) => Err(error),
        Ok(()) => invalid(
            &contaminated,
            "known RPATH contamination passed the audit".to_string(),
        ),
    }
}

fn write_provenance(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
    netd: &Path,
) -> Result<(), AuditError> {
    let directory = target_dir
        .join("release-provenance")
        .join(host.runtime_target());
    fs::create_dir_all(&directory).map_err(|source| AuditError::WriteProvenance {
        path: directory.clone(),
        source,
    })?;
    let release_target = target_dir.join("release-build").join(host.runtime_target());
    let go = release::go_program(&release_target, workspace_root, true)?;
    let cargo = release::tool("cargo")?;
    let rustc = release::tool("rustc")?;
    let zig = release::tool("zig")?;
    let cargo_zigbuild = release::tool("cargo-zigbuild")?;
    let toolchains = release::toolchains(workspace_root)?;
    let value = json!({
        "cargo": provenance_tool(&cargo, ["--version"] )?,
        "rustc": provenance_tool(&rustc, ["--version"] )?,
        "go": provenance_tool(&go, ["version"] )?,
        "zig": provenance_tool(&zig, ["version"] )?,
        "cargo_zigbuild": provenance_tool(&cargo_zigbuild, ["--version"] )?,
        "go_build": output_program_at(&go, ["version", "-m"], netd)?,
        "archives": {
            "go_darwin_arm64_sha256": toolchains.value("tools.go_darwin_arm64_sha256")?,
            "go_linux_amd64_sha256": toolchains.value("tools.go_linux_amd64_sha256")?,
            "go_linux_arm64_sha256": toolchains.value("tools.go_linux_arm64_sha256")?,
        },
        "release_toolchains": toolchains.values(),
        "apple_sdk": if matches!(host, HostTarget::MacosArm64) {
            Some(output_program(Path::new("/usr/bin/xcrun"), ["--sdk", "macosx", "--show-sdk-version"])? )
        } else {
            None
        },
    });
    let path = directory.join("toolchains.json");
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| AuditError::Invalid {
        path: path.clone(),
        reason: error.to_string(),
    })?;
    fs::write(&path, bytes).map_err(|source| AuditError::WriteProvenance { path, source })
}

fn provenance_tool(
    path: &Path,
    args: impl IntoIterator<Item = &'static str>,
) -> Result<serde_json::Value, AuditError> {
    Ok(json!({"path": path, "version": output_program(path, args)?}))
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

fn reject_build_paths(
    path: &Path,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
    let strings = output("/usr/bin/strings", [], path)?;
    let mut forbidden = vec![
        "/nix/store/".to_string(),
        "/opt/homebrew/".to_string(),
        "/usr/local/Cellar/".to_string(),
        "/opt/local/".to_string(),
        "/private/var/folders/".to_string(),
        "/var/folders/".to_string(),
        "/tmp/".to_string(),
        "/private/tmp/".to_string(),
    ];
    for root in [workspace_root, target_dir] {
        forbidden.push(format!("{}/", root.display()));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        forbidden.push(format!("{}/.cargo/", home.display()));
        forbidden.push(format!("{}/go/pkg/mod/", home.display()));
    }
    for value in forbidden {
        if value == "/tmp/" && !contains_forbidden_temporary_path(&strings, "/tmp/") {
            continue;
        }
        if strings.contains(&value) {
            return invalid(path, format!("contains build path {value}"));
        }
    }
    Ok(())
}

fn contains_forbidden_temporary_path(strings: &str, root: &str) -> bool {
    strings
        .match_indices(root)
        .any(|(offset, _)| !strings[offset..].starts_with("/tmp/silo-"))
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

fn output_program<'a>(
    program: &Path,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<String, AuditError> {
    let mut command = Command::new(program);
    command.args(args);
    output_command(command)
}

fn output_program_at<'a>(
    program: &Path,
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

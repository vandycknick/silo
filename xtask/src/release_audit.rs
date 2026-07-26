use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        return Err(AuditError::Invalid {
            path: target_dir.to_path_buf(),
            reason: "verify-runtime only qualifies release outputs".to_string(),
        });
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
            audit_static_elf(&stage.join("assets/agent"), workspace_root, target_dir)?;
            audit_static_elf(
                &target_dir
                    .join("release-build")
                    .join(host.runtime_target())
                    .join("aarch64-unknown-linux-musl/release/init"),
                workspace_root,
                target_dir,
            )?;
            verify_contaminated_macho(workspace_root, target_dir)?;
        }
        HostTarget::LinuxX86_64 | HostTarget::LinuxArm64 => {
            for (name, path) in host_binaries.iter().chain(staged_binaries.iter()) {
                audit_elf(name, path, workspace_root, target_dir)?;
            }
            audit_static_elf(&stage.join("assets/agent"), workspace_root, target_dir)?;
            audit_static_elf(
                &target_dir
                    .join("release-build")
                    .join(host.runtime_target())
                    .join(host.guest_target().triple())
                    .join("release/init"),
                workspace_root,
                target_dir,
            )?;
        }
    }
    write_provenance(target_dir, host, &release.join("netd"))
}

fn audit_macho(
    name: &str,
    path: &Path,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
    let dependencies = output("/usr/bin/otool", ["-L"], path)?;
    let actual = dependencies
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.trim()
                .split_once(" (")
                .map(|(path, _)| path.to_string())
        })
        .collect::<BTreeSet<_>>();
    let expected = macho_dependencies(name)?;
    if actual != expected {
        return invalid(
            path,
            format!("dylibs are {actual:?}, expected {expected:?}"),
        );
    }
    let load_commands = output("/usr/bin/otool", ["-l"], path)?;
    if load_commands.contains("LC_RPATH") {
        return invalid(path, "contains LC_RPATH".to_string());
    }
    let _ = output("/usr/bin/vtool", ["-show-build", "-arch", "arm64"], path)?;
    let _ = output("/usr/bin/nm", ["-u"], path)?;
    reject_build_paths(path, workspace_root, target_dir)?;
    Ok(())
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
        _ => {
            return Err(AuditError::Invalid {
                path: PathBuf::from(name),
                reason: "no Mach-O allowlist".to_string(),
            });
        }
    };
    Ok(values.iter().map(|value| (*value).to_string()).collect())
}

fn audit_elf(
    name: &str,
    path: &Path,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
    let program_headers = output("readelf", ["-lW"], path)?;
    let dynamic = output("readelf", ["-dW"], path)?;
    let objdump = output("objdump", ["-p"], path)?;
    let versions = output("readelf", ["--version-info"], path)?;
    if dynamic.contains("RPATH") || dynamic.contains("RUNPATH") {
        return invalid(path, "contains DT_RPATH or DT_RUNPATH".to_string());
    }
    if program_headers.contains("/nix/store") {
        return invalid(path, "uses a Nix dynamic interpreter".to_string());
    }
    let needed = elf_needed(&dynamic);
    if needed != elf_dependencies(name)? {
        return invalid(
            path,
            format!(
                "DT_NEEDED is {needed:?}, expected {:?}",
                elf_dependencies(name)?
            ),
        );
    }
    if objdump.contains("libkrun.so") || dynamic.contains("libkrun.so") {
        return invalid(path, "depends on libkrun.so".to_string());
    }
    reject_glibc_newer_than_239(path, &versions)?;
    reject_build_paths(path, workspace_root, target_dir)
}

fn audit_static_elf(
    path: &Path,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), AuditError> {
    if std::env::consts::OS == "macos" {
        let headers = output("objdump", ["-p"], path)?;
        if headers.contains("INTERP") || headers.contains("NEEDED") {
            return invalid(path, "guest binary is dynamically linked".to_string());
        }
        return reject_build_paths(path, workspace_root, target_dir);
    }
    let program_headers = output("readelf", ["-lW"], path)?;
    let dynamic = output("readelf", ["-dW"], path)?;
    if program_headers.contains("Requesting program interpreter")
        || dynamic.contains("Shared library:")
    {
        return invalid(path, "guest binary is dynamically linked".to_string());
    }
    reject_build_paths(path, workspace_root, target_dir)
}

fn elf_dependencies(name: &str) -> Result<BTreeSet<String>, AuditError> {
    let values: &[&str] = match name {
        "silo" => &[
            "libc.so.6",
            "libdl.so.2",
            "libgcc_s.so.1",
            "libm.so.6",
            "libpthread.so.0",
        ],
        "vmmon" => &[
            "libc.so.6",
            "libdl.so.2",
            "libgcc_s.so.1",
            "libm.so.6",
            "libpthread.so.0",
        ],
        "netd" => &[],
        "krun" => &[
            "libc.so.6",
            "libdl.so.2",
            "libgcc_s.so.1",
            "libm.so.6",
            "libpthread.so.0",
        ],
        _ => {
            return Err(AuditError::Invalid {
                path: PathBuf::from(name),
                reason: "no ELF allowlist".to_string(),
            });
        }
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
    let strings = output("strings", [], path)?;
    let mut forbidden = vec![
        "/nix/store".to_string(),
        "/opt/homebrew".to_string(),
        "/usr/local/Cellar".to_string(),
        "/opt/local".to_string(),
        "/private/var/folders".to_string(),
        "/var/folders".to_string(),
        "/tmp/rustc".to_string(),
        "/tmp/cargo".to_string(),
    ];
    forbidden.push(workspace_root.to_string_lossy().into_owned());
    forbidden.push(target_dir.to_string_lossy().into_owned());
    if let Some(value) = forbidden.iter().find(|value| strings.contains(*value)) {
        return invalid(path, format!("contains build path {value}"));
    }
    Ok(())
}

fn verify_contaminated_macho(workspace_root: &Path, target_dir: &Path) -> Result<(), AuditError> {
    let contaminated_target = target_dir.join("release-audit-contaminated");
    if contaminated_target.exists() {
        fs::remove_dir_all(&contaminated_target).map_err(|source| AuditError::WriteProvenance {
            path: contaminated_target.clone(),
            source,
        })?;
    }
    let cargo = release::tool("cargo", false)?;
    let mut build = Command::new(cargo);
    build
        .current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", &contaminated_target)
        .args(["build", "--locked", "--release", "-p", "cli"]);
    command::run(build)?;
    let contaminated = contaminated_target.join("release/silo");
    match audit_macho("silo", &contaminated, workspace_root, target_dir) {
        Err(AuditError::Invalid { .. }) => Ok(()),
        Err(error) => Err(error),
        Ok(()) => invalid(
            &contaminated,
            "ambient development build unexpectedly passed the contamination audit".to_string(),
        ),
    }
}

fn write_provenance(target_dir: &Path, host: HostTarget, netd: &Path) -> Result<(), AuditError> {
    let directory = target_dir
        .join("release-provenance")
        .join(host.runtime_target());
    fs::create_dir_all(&directory).map_err(|source| AuditError::WriteProvenance {
        path: directory.clone(),
        source,
    })?;
    let go = release::tool("go", false)?;
    let cargo = release::tool("cargo", false)?;
    let rustc = release::tool("rustc", false)?;
    let zig = release::tool("zig", false)?;
    let value = json!({
        "cargo": output_program(&cargo, ["--version"] )?,
        "rustc": output_program(&rustc, ["--version"] )?,
        "go": output_program(&go, ["version"] )?,
        "zig": output_program(&zig, ["version"] )?,
        "go_build": output_program_at(&go, ["version", "-m"], netd)?,
        "cargo_zigbuild": "0.23.0",
    });
    let path = directory.join("toolchains.json");
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| AuditError::Invalid {
        path: path.clone(),
        reason: error.to_string(),
    })?;
    fs::write(&path, bytes).map_err(|source| AuditError::WriteProvenance { path, source })
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

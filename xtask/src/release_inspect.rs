use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use thiserror::Error;

use crate::release_target::ReleaseTargetDescriptor;

#[derive(Debug)]
pub(crate) struct GuestExecutables {
    pub(crate) init: PathBuf,
    pub(crate) agent: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum ReleaseInspectionError {
    #[error("release inspection failed for {component} at {path}: {reason}")]
    Invalid {
        component: String,
        path: PathBuf,
        reason: String,
    },
    #[error("failed to run release inspection command {command}")]
    RunCommand { command: String, source: io::Error },
    #[error("release inspection command failed ({command}): {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("failed to read release component {path}")]
    Read { path: PathBuf, source: io::Error },
}

pub(crate) fn inspect_release(
    target: ReleaseTargetDescriptor,
    workspace: &Path,
    components: &Path,
    guest: &GuestExecutables,
) -> Result<Value, ReleaseInspectionError> {
    let mut reports = Vec::new();
    for component in ["silo", "vmmon", "netd", "krun"] {
        let path = components.join(component);
        reject_embedded_paths(component, &path, workspace)?;
        reports.push(if target.macos_minimum_version.is_some() {
            inspect_macho(component, &path, target)?
        } else {
            inspect_linux_elf(component, &path, target, false)?
        });
    }
    for (component, path) in [("guest-init", &guest.init), ("agent", &guest.agent)] {
        reject_embedded_paths(component, path, workspace)?;
        reports.push(inspect_linux_elf(component, path, target, true)?);
    }
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "target": target.name,
        "components": reports,
    }))
}

fn reject_embedded_paths(
    component: &str,
    path: &Path,
    workspace: &Path,
) -> Result<(), ReleaseInspectionError> {
    let bytes = fs::read(path).map_err(|source| ReleaseInspectionError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let workspace = workspace.as_os_str().as_encoded_bytes();
    if !workspace.is_empty() && contains_bytes(&bytes, workspace) {
        return invalid(component, path, "contains the build workspace path");
    }
    if let Some(forbidden) = non_rust_nix_path(&bytes) {
        return invalid(
            component,
            path,
            format!(
                "contains a Nix store path: {:?}",
                String::from_utf8_lossy(forbidden)
            ),
        );
    }
    Ok(())
}

fn non_rust_nix_path(bytes: &[u8]) -> Option<&[u8]> {
    const PREFIX: &[u8] = b"/nix/store/";
    const RUST_SOURCE: &[u8] = b"/lib/rustlib/src/rust/library/";
    let mut offset = 0;
    while let Some(relative) = bytes
        .get(offset..)
        .and_then(|remaining| find_bytes(remaining, PREFIX))
    {
        let start = offset + relative;
        let remaining = &bytes[start..];
        let end = remaining
            .iter()
            .position(|byte| !byte.is_ascii_graphic())
            .unwrap_or(remaining.len());
        let path = &remaining[..end];
        if !contains_bytes(path, RUST_SOURCE) {
            return Some(path);
        }
        offset = start + PREFIX.len();
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn inspect_macho(
    component: &str,
    path: &Path,
    target: ReleaseTargetDescriptor,
) -> Result<Value, ReleaseInspectionError> {
    let dependencies = run_capture(command_with_path("/usr/bin/otool", ["-L"], path))?;
    let dependencies = parse_macho_dependencies(&dependencies);
    for dependency in &dependencies {
        if dependency.contains("libkrun") {
            return invalid(component, path, "must not dynamically link libkrun");
        }
        if !(dependency.starts_with("/usr/lib/")
            || dependency.starts_with("/System/Library/Frameworks/"))
        {
            return invalid(
                component,
                path,
                format!("unexpected non-system dependency {dependency:?}"),
            );
        }
    }
    let load_commands = run_capture(command_with_path("/usr/bin/otool", ["-l"], path))?;
    if load_commands
        .lines()
        .any(|line| line.trim() == "cmd LC_RPATH")
    {
        return invalid(component, path, "contains LC_RPATH");
    }
    let minimum =
        parse_macos_minimum(&load_commands).ok_or_else(|| ReleaseInspectionError::Invalid {
            component: component.to_string(),
            path: path.to_path_buf(),
            reason: "has no LC_BUILD_VERSION minimum system version".to_string(),
        })?;
    let required = target.macos_minimum_version.unwrap_or("26.0");
    if version_parts(required) != version_parts(&minimum) {
        return invalid(
            component,
            path,
            format!("minimum macOS version must be {required}, found {minimum}"),
        );
    }
    Ok(serde_json::json!({
        "name": component,
        "format": "mach-o",
        "dependencies": dependencies,
        "minimumSystemVersion": minimum,
        "rpaths": [],
    }))
}

fn inspect_linux_elf(
    component: &str,
    path: &Path,
    target: ReleaseTargetDescriptor,
    require_static: bool,
) -> Result<Value, ReleaseInspectionError> {
    let readelf = if cfg!(target_os = "macos") {
        "llvm-readelf"
    } else {
        "readelf"
    };
    let dynamic = run_capture(command_with_path(readelf, ["-d", "-W"], path))?;
    if dynamic.contains("(RPATH)") || dynamic.contains("(RUNPATH)") {
        return invalid(component, path, "contains ELF RPATH or RUNPATH");
    }
    let dependencies = parse_elf_dependencies(&dynamic);
    if require_static && !dependencies.is_empty() {
        return invalid(
            component,
            path,
            format!("guest executable is dynamically linked: {dependencies:?}"),
        );
    }
    if dependencies
        .iter()
        .any(|dependency| dependency.contains("libkrun"))
    {
        return invalid(component, path, "must not dynamically link libkrun");
    }
    if !require_static {
        for dependency in &dependencies {
            if !allowed_linux_dependency(dependency) {
                return invalid(
                    component,
                    path,
                    format!("dependency {dependency:?} is not in the release allowlist"),
                );
            }
        }
    }
    let program_headers = run_capture(command_with_path(
        readelf,
        ["--program-headers", "-W"],
        path,
    ))?;
    let interpreter = parse_elf_interpreter(&program_headers);
    if require_static && interpreter.is_some() {
        return invalid(
            component,
            path,
            format!("guest executable has ELF interpreter {interpreter:?}"),
        );
    }
    let versions = run_capture(command_with_path(readelf, ["--version-info", "-W"], path))?;
    let glibc_versions = parse_glibc_versions(&versions);
    if let Some(baseline) = target.glibc_baseline {
        if let Some(required) = glibc_versions
            .iter()
            .find(|version| version_greater(version, baseline))
        {
            return invalid(
                component,
                path,
                format!("requires GLIBC_{required}, newer than baseline {baseline}"),
            );
        }
    }
    if !require_static {
        let mut ldd = Command::new("ldd");
        ldd.arg(path);
        let output = run_output(ldd)?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let static_binary = text.contains("not a dynamic executable")
            || text.contains("statically linked")
            || text.contains("not a dynamic Mach-O");
        if !output.status.success() && !static_binary {
            return Err(command_failure("ldd", &output));
        }
        if text.contains("not found") {
            return invalid(component, path, "has an unavailable shared library");
        }
        if text.contains("/nix/store/") {
            return invalid(
                component,
                path,
                "resolves a shared library from the Nix store",
            );
        }
        if let Some(resolved) = parse_non_system_ldd_path(&text) {
            return invalid(
                component,
                path,
                format!(
                    "shared library resolves outside /lib or /usr/lib: {}",
                    resolved.display()
                ),
            );
        }
    }
    Ok(serde_json::json!({
        "name": component,
        "format": "elf",
        "dependencies": dependencies,
        "glibcVersions": glibc_versions,
        "rpath": null,
        "static": dependencies.is_empty(),
        "interpreter": interpreter,
    }))
}

fn command_with_path<const N: usize>(program: &str, args: [&str; N], path: &Path) -> Command {
    let mut command = Command::new(program);
    command.args(args).arg(path);
    command
}

fn run_capture(command: Command) -> Result<String, ReleaseInspectionError> {
    let rendered = format!("{command:?}");
    let output = run_output(command)?;
    if !output.status.success() {
        return Err(command_failure(&rendered, &output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_output(mut command: Command) -> Result<Output, ReleaseInspectionError> {
    let rendered = format!("{command:?}");
    command
        .output()
        .map_err(|source| ReleaseInspectionError::RunCommand {
            command: rendered,
            source,
        })
}

fn command_failure(command: &str, output: &Output) -> ReleaseInspectionError {
    ReleaseInspectionError::CommandFailed {
        command: command.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    }
}

fn parse_macho_dependencies(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn parse_macos_minimum(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("minos "))
        .map(str::to_string)
}

fn parse_elf_dependencies(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| line.contains("(NEEDED)"))
        .filter_map(|line| {
            line.split_once('[')
                .and_then(|(_, value)| value.split_once(']'))
        })
        .map(|(value, _)| value.to_string())
        .collect()
}

fn parse_glibc_versions(output: &str) -> Vec<String> {
    let mut versions = output
        .split(|character: char| character.is_whitespace() || matches!(character, '(' | ')'))
        .filter_map(|token| token.strip_prefix("GLIBC_"))
        .filter(|version| {
            version
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.')
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    versions.sort_by_key(|version| version_parts(version));
    versions.dedup();
    versions
}

fn parse_elf_interpreter(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.split_once("Requesting program interpreter:")
            .map(|(_, value)| value.trim().trim_end_matches(']').to_string())
    })
}

fn allowed_linux_dependency(dependency: &str) -> bool {
    matches!(
        dependency,
        "libc.so.6"
            | "libcap-ng.so.0"
            | "libdl.so.2"
            | "libgcc_s.so.1"
            | "libm.so.6"
            | "libpthread.so.0"
            | "librt.so.1"
            | "libutil.so.1"
    )
}

fn parse_non_system_ldd_path(output: &str) -> Option<PathBuf> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        let candidate = if let Some((_, resolved)) = trimmed.split_once("=>") {
            resolved.split_whitespace().next()
        } else {
            trimmed.split_whitespace().next()
        }?;
        if !candidate.starts_with('/') {
            return None;
        }
        let path = PathBuf::from(candidate);
        if path.starts_with("/lib") || path.starts_with("/usr/lib") {
            None
        } else {
            Some(path)
        }
    })
}

fn version_greater(left: &str, right: &str) -> bool {
    version_parts(left) > version_parts(right)
}

fn version_parts(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(u32::MAX))
        .collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn invalid<T>(
    component: &str,
    path: &Path,
    reason: impl Into<String>,
) -> Result<T, ReleaseInspectionError> {
    Err(ReleaseInspectionError::Invalid {
        component: component.to_string(),
        path: path.to_path_buf(),
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use crate::release_inspect::{
        allowed_linux_dependency, contains_bytes, non_rust_nix_path, parse_elf_dependencies,
        parse_elf_interpreter, parse_glibc_versions, parse_macho_dependencies, parse_macos_minimum,
        parse_non_system_ldd_path, version_greater,
    };

    #[test]
    fn parses_macho_dependencies_and_minimum_version() {
        let dependencies = parse_macho_dependencies(
            "/tmp/silo:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization (compatibility version 1.0.0)\n",
        );
        assert_eq!(dependencies.len(), 2);
        assert_eq!(
            parse_macos_minimum("cmd LC_BUILD_VERSION\n  minos 26.0\n"),
            Some("26.0".to_string())
        );
    }

    #[test]
    fn parses_elf_dependencies_and_sorted_glibc_versions() {
        let dependencies = parse_elf_dependencies(
            "0x1 (NEEDED) Shared library: [libc.so.6]\n0x1 (NEEDED) Shared library: [libm.so.6]",
        );
        assert_eq!(dependencies, ["libc.so.6", "libm.so.6"]);
        let versions = parse_glibc_versions(
            "Name: GLIBC_2.34 Flags: none\nName: GLIBC_2.2.5\nName: GLIBC_PRIVATE",
        );
        assert_eq!(versions, ["2.2.5", "2.34"]);
        assert!(version_greater("2.40", "2.39"));
        assert!(!version_greater("2.9", "2.39"));
        assert_eq!(
            parse_elf_interpreter("[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]"),
            Some("/lib64/ld-linux-x86-64.so.2".to_string())
        );
        assert!(allowed_linux_dependency("libc.so.6"));
        assert!(!allowed_linux_dependency("libkrun.so.1"));
        assert_eq!(
            parse_non_system_ldd_path("libfoo.so.1 => /opt/silo/libfoo.so.1 (0x0)"),
            Some(std::path::PathBuf::from("/opt/silo/libfoo.so.1"))
        );
    }

    #[test]
    fn raw_path_scan_finds_exact_byte_sequences() {
        assert!(contains_bytes(b"prefix/nix/store/object", b"/nix/store/"));
        assert!(!contains_bytes(b"prefix/nix/stores/object", b"/nix/store/"));
    }

    #[test]
    fn raw_path_scan_allows_only_nix_rust_standard_library_sources() {
        assert!(non_rust_nix_path(
            b"/nix/store/hash-rust/lib/rustlib/src/rust/library/core/src/time.rs\0"
        )
        .is_none());
        assert_eq!(
            non_rust_nix_path(b"/nix/store/hash-libiconv/lib/libiconv.2.dylib\0"),
            Some(b"/nix/store/hash-libiconv/lib/libiconv.2.dylib".as_slice())
        );
        assert!(non_rust_nix_path(b"/nix/store/hash-rust/bin/rustc\0").is_some());
    }
}

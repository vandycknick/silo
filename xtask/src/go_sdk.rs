use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::components::BuildContext;

struct Target {
    name: &'static str,
    bridge_input: &'static str,
    bridge_bundle: &'static str,
    source_file: &'static str,
    build_tag: &'static str,
    output_name: &'static str,
}

const TARGETS: [Target; 3] = [
    Target {
        name: "darwin-arm64",
        bridge_input: "libsilo_go_ffi.dylib",
        bridge_bundle: "libsilo_go_ffi-darwin-arm64.dylib",
        source_file: "bundle_darwin_arm64.go",
        build_tag: "darwin && arm64",
        output_name: "libsilo_go_ffi.dylib",
    },
    Target {
        name: "linux-amd64-gnu",
        bridge_input: "libsilo_go_ffi.so",
        bridge_bundle: "libsilo_go_ffi-linux-amd64.so",
        source_file: "bundle_linux_amd64.go",
        build_tag: "linux && amd64",
        output_name: "libsilo_go_ffi.so",
    },
    Target {
        name: "linux-arm64-gnu",
        bridge_input: "libsilo_go_ffi.so",
        bridge_bundle: "libsilo_go_ffi-linux-arm64.so",
        source_file: "bundle_linux_arm64.go",
        build_tag: "linux && arm64",
        output_name: "libsilo_go_ffi.so",
    },
];

#[derive(Debug, Error)]
pub enum GoSdkError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid Go SDK release input {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

pub fn run_example(context: &BuildContext<'_>, example: &str) -> Result<(), GoSdkError> {
    if example.is_empty()
        || !example
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return invalid(
            &context.workspace_root.join("sdk/go/examples"),
            format!("invalid example name {example:?}"),
        );
    }
    let example_path = context
        .workspace_root
        .join("sdk/go/examples")
        .join(example)
        .join("main.go");
    if !example_path.is_file() {
        return invalid(&example_path, "example does not exist");
    }

    let ffi_path = context
        .target_dir
        .join(context.profile.directory())
        .join(context.host.go_ffi_library());
    let runtime_root = context
        .target_dir
        .join("silo-runtime")
        .join(context.host.runtime_target())
        .join(context.profile.directory());
    let mut go = Command::new("go");
    go.current_dir(context.workspace_root)
        .env("CGO_ENABLED", "1")
        .env("SILO_GO_FFI_PATH", ffi_path)
        .env("SILO_EXAMPLE_RUNTIME_ROOT", runtime_root)
        .arg("-C")
        .arg("sdk/go")
        .arg("run")
        .arg(format!("./examples/{example}"));
    command::run(go)?;
    Ok(())
}

pub fn assemble(workspace_root: &Path, packages_root: &Path) -> Result<(), GoSdkError> {
    let version_path = workspace_root.join("VERSION");
    let version = read_string(&version_path)?.trim().to_string();
    if version.is_empty() {
        return invalid(&version_path, "version is empty");
    }

    validate_release_inputs(packages_root, &version)?;

    let mut runtime_digests = Vec::with_capacity(TARGETS.len());
    for target in &TARGETS {
        let target_root = packages_root.join(&version).join(target.name);
        let archive = target_root.join(format!("silo-runtime-{version}-{}.tar.zst", target.name));
        runtime_digests.push((target.name, verified_digest(&archive)?));

        let bridge = target_root.join("go-ffi").join(target.bridge_input);
        let bridge_digest = verified_digest(&bridge)?;
        let bundle = workspace_root
            .join("sdk/go/internal/bundle/bundles")
            .join(target.bridge_bundle);
        create_parent(&bundle)?;
        copy_file(&bridge, &bundle)?;
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o755)).map_err(|source| {
            GoSdkError::Io {
                action: "set permissions on",
                path: bundle.clone(),
                source,
            }
        })?;

        let source = format!(
            "//go:build {build_tag}\n\npackage bundle\n\nimport _ \"embed\"\n\nconst (\n\tplatformSupported = true\n\tplatformTarget    = {target_name:?}\n\tplatformFilename  = {output_name:?}\n\tembeddedDigest    = {bridge_digest:?}\n)\n\n//go:embed bundles/{bridge_bundle}\nvar embeddedLibrary []byte\n",
            build_tag = target.build_tag,
            target_name = target.name,
            output_name = target.output_name,
            bridge_bundle = target.bridge_bundle,
        );
        write_file(
            &workspace_root
                .join("sdk/go/internal/bundle")
                .join(target.source_file),
            source.as_bytes(),
        )?;
    }

    let darwin_digest = runtime_digest(&runtime_digests, "darwin-arm64")?;
    let linux_amd64_digest = runtime_digest(&runtime_digests, "linux-amd64-gnu")?;
    let linux_arm64_digest = runtime_digest(&runtime_digests, "linux-arm64-gnu")?;
    let metadata = format!(
        "package silo\n\nconst defaultRuntimeReleaseOrigin = \"https://github.com/vandycknick/silo/releases/download\"\n\ntype runtimeArchiveMetadata struct {{\n\tversion string\n\ttarget  RuntimeTarget\n\tname    string\n\tsha256  string\n}}\n\nvar runtimeArchives = map[RuntimeTarget]runtimeArchiveMetadata{{\n\tRuntimeTargetDarwinARM64: {{\n\t\tversion: Version,\n\t\ttarget:  RuntimeTargetDarwinARM64,\n\t\tname:    \"silo-runtime-\" + Version + \"-darwin-arm64.tar.zst\",\n\t\tsha256:  {darwin:?},\n\t}},\n\tRuntimeTargetLinuxAMD64GNU: {{\n\t\tversion: Version,\n\t\ttarget:  RuntimeTargetLinuxAMD64GNU,\n\t\tname:    \"silo-runtime-\" + Version + \"-linux-amd64-gnu.tar.zst\",\n\t\tsha256:  {linux_amd64:?},\n\t}},\n\tRuntimeTargetLinuxARM64GNU: {{\n\t\tversion: Version,\n\t\ttarget:  RuntimeTargetLinuxARM64GNU,\n\t\tname:    \"silo-runtime-\" + Version + \"-linux-arm64-gnu.tar.zst\",\n\t\tsha256:  {linux_arm64:?},\n\t}},\n}}\n",
        darwin = darwin_digest,
        linux_amd64 = linux_amd64_digest,
        linux_arm64 = linux_arm64_digest,
    );
    write_file(
        &workspace_root.join("sdk/go/runtime_metadata.go"),
        metadata.as_bytes(),
    )
}

fn validate_release_inputs(packages_root: &Path, version: &str) -> Result<(), GoSdkError> {
    let mut missing = Vec::new();
    for target in &TARGETS {
        let target_root = packages_root.join(version).join(target.name);
        let archive = target_root.join(format!("silo-runtime-{version}-{}.tar.zst", target.name));
        let bridge = target_root.join("go-ffi").join(target.bridge_input);
        for path in [
            archive.clone(),
            append_suffix(&archive, ".sha256")?,
            bridge.clone(),
            append_suffix(&bridge, ".sha256")?,
        ] {
            if !path.is_file() {
                missing.push(path);
            }
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let paths = missing
        .iter()
        .map(|path| format!("  - {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n");
    invalid(
        packages_root,
        format!(
            "release assembly requires qualified runtime archives, native bridges, and checksum sidecars for every supported target; this command is not needed for development builds or examples. Missing:\n{paths}"
        ),
    )
}

fn runtime_digest<'a>(digests: &'a [(&str, String)], target: &str) -> Result<&'a str, GoSdkError> {
    digests
        .iter()
        .find_map(|(name, digest)| (*name == target).then_some(digest.as_str()))
        .ok_or_else(|| GoSdkError::Invalid {
            path: PathBuf::from(target),
            reason: "target digest was not assembled".to_string(),
        })
}

fn verified_digest(path: &Path) -> Result<String, GoSdkError> {
    let actual = sha256(path)?;
    let sidecar_path = append_suffix(path, ".sha256")?;
    let sidecar = read_string(&sidecar_path)?;
    let expected = sidecar
        .split_whitespace()
        .next()
        .ok_or_else(|| GoSdkError::Invalid {
            path: sidecar_path.clone(),
            reason: "checksum sidecar is empty".to_string(),
        })?;
    if !expected.eq_ignore_ascii_case(&actual) {
        return invalid(
            path,
            format!("SHA-256 sidecar declares {expected}, calculated {actual}"),
        );
    }
    Ok(actual)
}

fn sha256(path: &Path) -> Result<String, GoSdkError> {
    let mut file = fs::File::open(path).map_err(|source| GoSdkError::Io {
        action: "open for SHA-256",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| GoSdkError::Io {
            action: "read for SHA-256",
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn append_suffix(path: &Path, suffix: &str) -> Result<PathBuf, GoSdkError> {
    let name = path.file_name().ok_or_else(|| GoSdkError::Invalid {
        path: path.to_path_buf(),
        reason: "path has no file name".to_string(),
    })?;
    let mut sidecar = name.to_os_string();
    sidecar.push(suffix);
    Ok(path.with_file_name(sidecar))
}

fn create_parent(path: &Path) -> Result<(), GoSdkError> {
    let parent = path.parent().ok_or_else(|| GoSdkError::Invalid {
        path: path.to_path_buf(),
        reason: "path has no parent".to_string(),
    })?;
    fs::create_dir_all(parent).map_err(|source| GoSdkError::Io {
        action: "create directory",
        path: parent.to_path_buf(),
        source,
    })
}

fn copy_file(source_path: &Path, destination: &Path) -> Result<(), GoSdkError> {
    fs::copy(source_path, destination)
        .map(|_| ())
        .map_err(|source| GoSdkError::Io {
            action: "copy bridge to",
            path: destination.to_path_buf(),
            source,
        })
}

fn write_file(path: &Path, contents: &[u8]) -> Result<(), GoSdkError> {
    create_parent(path)?;
    fs::write(path, contents).map_err(|source| GoSdkError::Io {
        action: "write",
        path: path.to_path_buf(),
        source,
    })
}

fn read_file(path: &Path) -> Result<Vec<u8>, GoSdkError> {
    fs::read(path).map_err(|source| GoSdkError::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })
}

fn read_string(path: &Path) -> Result<String, GoSdkError> {
    String::from_utf8(read_file(path)?).map_err(|source| GoSdkError::Invalid {
        path: path.to_path_buf(),
        reason: format!("file is not UTF-8: {source}"),
    })
}

fn invalid<T>(path: &Path, reason: impl Into<String>) -> Result<T, GoSdkError> {
    Err(GoSdkError::Invalid {
        path: path.to_path_buf(),
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::components::BuildContext;
    use crate::go_sdk::{assemble, run_example, sha256, TARGETS};
    use crate::profiles::Profile;
    use crate::targets::HostTarget;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "silo-xtask-{name}-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn assembles_all_qualified_targets() {
        let repository = TestDirectory::new("repository");
        let packages = TestDirectory::new("packages");
        fs::write(repository.path().join("VERSION"), "0.1.0\n").expect("write version");

        for target in &TARGETS {
            let directory = packages.path().join("0.1.0").join(target.name);
            fs::create_dir_all(directory.join("go-ffi")).expect("create target fixture");
            let archive = directory.join(format!("silo-runtime-0.1.0-{}.tar.zst", target.name));
            write_qualified(&archive, format!("archive-{}", target.name).as_bytes());
            let bridge = directory.join("go-ffi").join(target.bridge_input);
            write_qualified(&bridge, format!("bridge-{}", target.name).as_bytes());
        }

        assemble(repository.path(), packages.path()).expect("assemble Go SDK");
        let metadata = fs::read_to_string(repository.path().join("sdk/go/runtime_metadata.go"))
            .expect("read generated metadata");
        assert_eq!(metadata.matches("sha256:").count(), 3);
        for target in &TARGETS {
            assert!(repository
                .path()
                .join("sdk/go/internal/bundle/bundles")
                .join(target.bridge_bundle)
                .is_file());
            let source = fs::read_to_string(
                repository
                    .path()
                    .join("sdk/go/internal/bundle")
                    .join(target.source_file),
            )
            .expect("read generated bundle source");
            assert!(source.contains(target.bridge_bundle));
        }
    }

    #[test]
    fn rejects_unsafe_example_names() {
        let repository = TestDirectory::new("example-repository");
        let target = TestDirectory::new("example-target");
        let context = BuildContext {
            workspace_root: repository.path(),
            target_dir: target.path(),
            profile: Profile::Debug,
            host: HostTarget::LinuxX86_64,
        };

        let error = run_example(&context, "../basic").expect_err("reject unsafe name");
        assert!(error.to_string().contains("invalid example name"));
    }

    #[test]
    fn explains_missing_release_inputs() {
        let repository = TestDirectory::new("missing-repository");
        let packages = TestDirectory::new("missing-packages");
        fs::write(repository.path().join("VERSION"), "0.1.0\n").expect("write version");

        let error =
            assemble(repository.path(), packages.path()).expect_err("reject missing inputs");
        let message = error.to_string();
        assert!(message.contains("not needed for development builds or examples"));
        assert!(message.contains("darwin-arm64"));
        assert!(message.contains("linux-amd64-gnu"));
        assert!(message.contains("linux-arm64-gnu"));
    }

    #[test]
    fn rejects_a_mismatched_sidecar() {
        let repository = TestDirectory::new("invalid-repository");
        let packages = TestDirectory::new("invalid-packages");
        fs::write(repository.path().join("VERSION"), "0.1.0\n").expect("write version");
        for target in &TARGETS {
            let directory = packages.path().join("0.1.0").join(target.name);
            fs::create_dir_all(directory.join("go-ffi")).expect("create target fixture");
            let archive = directory.join(format!("silo-runtime-0.1.0-{}.tar.zst", target.name));
            write_qualified(&archive, b"archive");
            write_qualified(
                &directory.join("go-ffi").join(target.bridge_input),
                b"bridge",
            );
        }
        let target = &TARGETS[0];
        let archive = packages
            .path()
            .join("0.1.0")
            .join(target.name)
            .join(format!("silo-runtime-0.1.0-{}.tar.zst", target.name));
        fs::write(append_for_test(&archive), "0000  archive\n").expect("write sidecar");

        let error = assemble(repository.path(), packages.path()).expect_err("reject sidecar");
        assert!(error.to_string().contains("SHA-256 sidecar"));
    }

    fn write_qualified(path: &Path, contents: &[u8]) {
        fs::write(path, contents).expect("write fixture");
        let digest = sha256(path).expect("hash fixture");
        fs::write(
            append_for_test(path),
            format!(
                "{digest}  {}\n",
                path.file_name().unwrap().to_string_lossy()
            ),
        )
        .expect("write checksum fixture");
    }

    fn append_for_test(path: &Path) -> std::path::PathBuf {
        let mut name = path.file_name().unwrap().to_os_string();
        name.push(".sha256");
        path.with_file_name(name)
    }
}

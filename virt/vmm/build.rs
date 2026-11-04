mod build_inputs;
mod dependency_source;

use std::collections::BTreeMap;
use std::error::Error;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    let root = std::fs::canonicalize(Path::new(&manifest).join("../.."))?;
    let lock_path = root.join("Cargo.lock");
    let workspace_path = root.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    println!("cargo:rerun-if-changed={}", workspace_path.display());
    let lock = std::fs::read_to_string(lock_path)?;
    let workspace = std::fs::read_to_string(workspace_path)?;
    let source = dependency_source::resolve_dependency(&workspace, &lock)?;
    let source = observe_native_source(&root, source)?;
    let target = std::env::var("TARGET")?;
    let profile = std::env::var("PROFILE")?;
    let (observed, declared) = collect_build_inputs(&root, &workspace)?;
    println!(
        "cargo:rustc-env=SILO_BUILD_INPUT_FINGERPRINT={}",
        build_inputs::fingerprint(&observed)
    );
    println!("cargo:rustc-env=SILO_DECLARED_FEATURES_FINGERPRINT={declared}");
    println!("cargo:rustc-env=SILO_LIBKRUN_SOURCE_KIND={}", source.kind);
    println!("cargo:rustc-env=SILO_LIBKRUN_SOURCE_ROOT={}", source.root);
    println!("cargo:rustc-env=SILO_LIBKRUN_SOURCE_STATE={}", source.state);
    println!(
        "cargo:rustc-env=SILO_LIBKRUN_SOURCE_CONTENT={}",
        source.content
    );
    println!("cargo:rustc-env=SILO_LIBKRUN_REVISION={}", source.revision);
    println!("cargo:rustc-env=SILO_BUILD_TARGET={target}");
    println!("cargo:rustc-env=SILO_BUILD_PROFILE={profile}");
    Ok(())
}

struct NativeSource {
    kind: &'static str,
    root: String,
    revision: String,
    state: &'static str,
    content: String,
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim_end_matches('\n').to_owned())
}

fn observe_native_source(
    workspace: &Path,
    source: dependency_source::DependencySource<'_>,
) -> Result<NativeSource, Box<dyn Error>> {
    let crate_path = match source {
        dependency_source::DependencySource::Git { revision } => {
            return Ok(NativeSource {
                kind: "git",
                root: String::new(),
                revision: revision.into(),
                state: "revision-bound",
                content: build_inputs::fingerprint(&BTreeMap::from([(
                    "git.revision".into(),
                    revision.as_bytes().to_vec(),
                )])),
            });
        }
        dependency_source::DependencySource::Path { crate_path } => {
            std::fs::canonicalize(workspace.join(crate_path))?
        }
    };
    let manifest_path = crate_path.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let manifest = std::fs::read_to_string(&manifest_path)?;
    if !manifest
        .lines()
        .any(|line| dependency_source::quoted_field(line, "name") == Some("libkrun"))
    {
        return Err("libkrun patch does not name the native libkrun package".into());
    }
    let workspace_root = crate_path.ancestors().find(|ancestor| {
        std::fs::read_to_string(ancestor.join("Cargo.toml"))
            .is_ok_and(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
    });
    let git_root = git(&crate_path, &["rev-parse", "--show-toplevel"])
        .and_then(|path| std::fs::canonicalize(path).ok())
        .filter(|root| workspace_root == Some(root.as_path()));
    let root = git_root
        .as_deref()
        .or(workspace_root)
        .unwrap_or(&crate_path);
    let head = git_root
        .as_ref()
        .and_then(|_| git(root, &["rev-parse", "--verify", "HEAD"]));
    let status = git_root.as_ref().and_then(|_| {
        git(
            root,
            &[
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        )
    });
    let tracked = git(root, &["ls-files", "-z"]);
    if let Some(tracked) = &tracked {
        for file in tracked.split('\0').filter(|file| !file.is_empty()) {
            let path = root.join(file);
            println!("cargo:rerun-if-changed={}", path.display());
            // Parent directories notice new untracked inputs alongside tracked files.
            if let Some(parent) = path.parent().filter(|parent| *parent != root) {
                println!("cargo:rerun-if-changed={}", parent.display());
            }
        }
    }
    let mut metadata_observed = true;
    for name in [
        "HEAD",
        "index",
        "packed-refs",
        "refs",
        "config",
        "info/exclude",
    ] {
        if let Some(path) = git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-path", name],
        ) {
            println!("cargo:rerun-if-changed={path}");
        } else {
            metadata_observed = false;
        }
    }
    println!("cargo:rerun-if-changed={}", root.join(".git").display());
    let content = build_inputs::source_content(root, |path| {
        println!("cargo:rerun-if-changed={}", path.display());
    });
    let after = git(root, &["rev-parse", "--verify", "HEAD"]);
    let after_status = git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    );
    let state = match (&head, &status, &after, &after_status) {
        (Some(head), Some(status), Some(after), Some(after_status))
            if git_root.is_some()
                && metadata_observed
                && tracked.is_some()
                && head == after
                && status == after_status
                && content.is_ok() =>
        {
            if status.is_empty() {
                "clean"
            } else {
                "dirty"
            }
        }
        _ => "unknown",
    };
    let content = match content {
        Ok(content) => content,
        Err(error) => {
            println!("cargo:warning=native source content is unattested: {error}");
            "unknown".into()
        }
    };
    Ok(NativeSource {
        kind: "path",
        root: root
            .to_str()
            .ok_or("native source root is not UTF-8")?
            .into(),
        revision: head.unwrap_or_else(|| "unknown".into()),
        state,
        content,
    })
}

type BuildInputs = BTreeMap<String, Vec<u8>>;

fn collect_build_inputs(
    root: &Path,
    workspace: &str,
) -> Result<(BuildInputs, String), Box<dyn Error>> {
    let mut declared = BuildInputs::new();
    declared.insert("manifest.Cargo.toml".into(), workspace.as_bytes().to_vec());
    let mut members = workspace
        .lines()
        .skip_while(|line| line.trim() != "members = [");
    if members.next().is_none() {
        return Err("workspace members must use the explicit multiline manifest form".into());
    }
    for line in members {
        let line = line.trim();
        if line == "]" {
            break;
        }
        let member = line
            .trim_end_matches(',')
            .strip_prefix('"')
            .and_then(|line| line.strip_suffix('"'))
            .ok_or("workspace member is not an explicit quoted path")?;
        let path = root.join(member).join("Cargo.toml");
        println!("cargo:rerun-if-changed={}", path.display());
        declared.insert(
            format!("manifest.{member}/Cargo.toml"),
            std::fs::read(path)?,
        );
    }

    let declared = build_inputs::fingerprint(&declared);
    let mut observed = BuildInputs::new();
    observed.insert(
        "declared-manifests.fingerprint".into(),
        declared.as_bytes().to_vec(),
    );
    observed.insert(
        "lock.Cargo.lock".into(),
        std::fs::read(root.join("Cargo.lock"))?,
    );
    for path in [
        root.join("virt/vmm/build.rs"),
        root.join("virt/vmm/build_inputs.rs"),
        root.join("virt/vmm/dependency_source.rs"),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.strip_prefix(root)?.to_string_lossy();
        observed.insert(format!("source.{name}"), std::fs::read(&path)?);
    }
    for (name, value) in std::env::vars_os() {
        let Some(name) = name.to_str() else {
            continue;
        };
        if build_inputs::observed_environment(name) {
            println!("cargo:rerun-if-env-changed={name}");
            observed.insert(format!("environment.{name}"), value.as_bytes().to_vec());
        }
    }
    for name in [
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_HOME",
        "HOME",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for (index, ancestor) in root.ancestors().enumerate() {
        for filename in ["config", "config.toml"] {
            observe_config(
                &mut observed,
                format!("cargo-config.ancestor.{index}.{filename}"),
                &ancestor.join(".cargo").join(filename),
            )?;
        }
    }
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
        });
    if let Some(home) = cargo_home {
        for filename in ["config", "config.toml"] {
            observe_config(
                &mut observed,
                format!("cargo-config.home.{filename}"),
                &home.join(filename),
            )?;
        }
    }
    let compiler = std::env::var_os("RUSTC").ok_or("Cargo did not expose RUSTC")?;
    let version = Command::new(compiler)
        .args(["--version", "--verbose"])
        .output()?;
    if !version.status.success() {
        return Err("could not identify the effective Rust compiler".into());
    }
    observed.insert("compiler.version".into(), version.stdout);
    Ok((observed, declared))
}

fn observe_config(
    inputs: &mut BuildInputs,
    name: String,
    path: &Path,
) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={}", path.display());
    match std::fs::read(path) {
        Ok(bytes) => {
            inputs.insert(format!("{name}.present"), b"1".to_vec());
            inputs.insert(name, bytes);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            inputs.insert(format!("{name}.present"), b"0".to_vec());
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

//! Canonical fingerprints of observable build inputs, never qualification evidence.
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

pub fn observed_environment(name: &str) -> bool {
    matches!(
        name,
        "PROFILE"
            | "OPT_LEVEL"
            | "DEBUG"
            | "HOST"
            | "TARGET"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTFLAGS"
            | "CARGO_BUILD_RUSTFLAGS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
    ) || name.starts_with("CARGO_CFG_")
        || name.starts_with("CARGO_FEATURE_")
        || name.starts_with("CARGO_PROFILE_")
        || name.starts_with("CARGO_TARGET_")
}

pub fn fingerprint(inputs: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"silo-observed-build-inputs-v1\0");
    for (name, value) in inputs {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in hash.finalize() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    encoded
}

/// Content under the native source/build-input roots, including ignored files.
/// Directory watches also notice newly added files, not only tracked modifications.
pub fn source_content(
    root: &std::path::Path,
    mut watch: impl FnMut(&std::path::Path),
) -> Result<String, Box<dyn std::error::Error>> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        inputs: &mut BTreeMap<String, Vec<u8>>,
        watch: &mut impl FnMut(&std::path::Path),
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read as _;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;
        watch(path);
        let name = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("native input path is not UTF-8")?;
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                inputs.insert(format!("absent.{name}"), Vec::new());
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        inputs.insert(
            format!("mode.{name}"),
            metadata.mode().to_be_bytes().to_vec(),
        );
        if metadata.is_dir() {
            inputs.insert(format!("directory.{name}"), Vec::new());
            for entry in std::fs::read_dir(path)? {
                visit(root, &entry?.path(), inputs, watch)?;
            }
        } else {
            if metadata.file_type().is_symlink() {
                inputs.insert(
                    format!("symlink.{name}"),
                    std::fs::read_link(path)?.as_os_str().as_bytes().to_vec(),
                );
                if !std::fs::metadata(path)?.is_file() {
                    return Err("native input directory symlinks are not content-attestable".into());
                }
                watch(&std::fs::canonicalize(path)?);
            } else if !metadata.is_file() {
                return Err("native input is not a file or directory".into());
            }
            let mut file = std::fs::File::open(path)?;
            let mut hash = Sha256::new();
            let mut bytes = [0u8; 16384];
            loop {
                let count = file.read(&mut bytes)?;
                if count == 0 {
                    break;
                }
                hash.update(&bytes[..count]);
            }
            inputs.insert(format!("file.{name}"), hash.finalize().to_vec());
        }
        Ok(())
    }
    let mut inputs = BTreeMap::new();
    for path in [
        "src",
        "init",
        "include",
        ".cargo",
        "Cargo.toml",
        "Cargo.lock",
        "Makefile",
        ".gitignore",
        "rust-toolchain",
        "rust-toolchain.toml",
    ] {
        visit(root, &root.join(path), &mut inputs, &mut watch)?;
    }
    Ok(fingerprint(&inputs))
}

#[cfg(test)]
mod tests {
    use crate::build_inputs::{fingerprint, observed_environment, source_content};
    use std::collections::BTreeMap;

    #[test]
    fn capabilities_observed_build_fingerprint_distinguishes_effective_inputs() {
        let inputs = BTreeMap::from([
            ("PROFILE".into(), b"release".to_vec()),
            ("OPT_LEVEL".into(), b"3".to_vec()),
            ("DEBUG".into(), b"false".to_vec()),
            ("CARGO_CFG_TARGET_FEATURE".into(), b"fxsr,sse,sse2".to_vec()),
            ("CARGO_ENCODED_RUSTFLAGS".into(), Vec::new()),
            ("compiler.version".into(), b"rustc revision-a".to_vec()),
            (
                "manifest.Cargo.toml".into(),
                b"features=[\"blk\",\"net\"]".to_vec(),
            ),
        ]);
        let baseline = fingerprint(&inputs);
        for (name, value) in [
            ("OPT_LEVEL", "2"),
            ("DEBUG", "true"),
            ("CARGO_CFG_TARGET_FEATURE", "avx,fxsr,sse,sse2"),
            ("CARGO_ENCODED_RUSTFLAGS", "-C\u{1f}target-cpu=native"),
            ("compiler.version", "rustc revision-b"),
            ("manifest.Cargo.toml", "features=[\"blk\",\"gpu\",\"net\"]"),
        ] {
            let mut changed = inputs.clone();
            changed.insert(name.into(), value.as_bytes().to_vec());
            assert_ne!(fingerprint(&changed), baseline, "{name} was not bound");
        }
        assert_eq!(baseline.len(), 64);
    }

    #[test]
    fn capabilities_observed_build_fingerprint_is_canonical_and_unambiguous() {
        let first = BTreeMap::from([("a".into(), b"bc".to_vec())]);
        let second = BTreeMap::from([("ab".into(), b"c".to_vec())]);
        assert_ne!(fingerprint(&first), fingerprint(&second));
        let ordered =
            BTreeMap::from([("b".into(), b"two".to_vec()), ("a".into(), b"one".to_vec())]);
        let reordered =
            BTreeMap::from([("a".into(), b"one".to_vec()), ("b".into(), b"two".to_vec())]);
        assert_eq!(fingerprint(&ordered), fingerprint(&reordered));
        for name in [
            "OPT_LEVEL",
            "DEBUG",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_CFG_TARGET_FEATURE",
            "CARGO_CFG_PANIC",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
        ] {
            assert!(observed_environment(name));
        }
        for name in [
            "SILO_HOME",
            "SILO_QUALIFICATION",
            "OUT_DIR",
            "CARGO_MANIFEST_DIR",
        ] {
            assert!(!observed_environment(name));
        }
    }

    #[test]
    fn capabilities_native_source_content_tracks_changes_additions_deletions_and_watches() {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            Directory(std::env::temp_dir().join(format!("silo-source-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir_all(root.0.join("src")).expect("create source fixture");
        let source = root.0.join("src/native.rs");
        std::fs::write(&source, b"first").expect("write source");
        let mut watched = Vec::new();
        let baseline = source_content(&root.0, |path| watched.push(path.to_path_buf()))
            .expect("content identity");
        assert!(watched.contains(&source));
        assert!(watched.contains(&root.0.join("src")));
        assert!(watched.contains(&root.0.join("Cargo.toml")));
        std::fs::write(&source, b"other").expect("change same-length source");
        assert_ne!(
            source_content(&root.0, |_| {}).expect("changed content"),
            baseline
        );
        std::fs::write(&source, b"first").expect("restore source");
        assert_eq!(
            source_content(&root.0, |_| {}).expect("restored content"),
            baseline
        );
        let added = root.0.join("src/new.rs");
        std::fs::write(&added, b"new").expect("create untracked source");
        assert_ne!(
            source_content(&root.0, |_| {}).expect("added content"),
            baseline
        );
        std::fs::remove_file(&added).expect("remove added source");
        assert_eq!(
            source_content(&root.0, |_| {}).expect("restored tree"),
            baseline
        );
        std::fs::remove_file(&source).expect("delete source");
        assert_ne!(
            source_content(&root.0, |_| {}).expect("deleted content"),
            baseline
        );
    }
}

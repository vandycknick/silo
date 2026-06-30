use std::path::{Path, PathBuf};

use eyre::Context;
use vm_spec::{Boot, Kernel, VmSpec};

use crate::constants::ASSET_INITRAMFS_FILENAME;
use crate::machine::resolve_mount_location;
use crate::paths::LocalPaths;

pub(crate) struct LaunchSpecInput<'a> {
    pub(crate) paths: &'a LocalPaths,
    pub(crate) relative_mount_base: &'a Path,
    pub(crate) spec: VmSpec,
}

pub(crate) fn prepare_launch_spec(input: LaunchSpecInput<'_>) -> eyre::Result<VmSpec> {
    let mut spec = input.spec;
    normalize_mount_sources(&mut spec, input.relative_mount_base)?;
    prepare_default_initramfs(input.paths, &mut spec)?;
    Ok(spec)
}

pub(crate) fn write_launch_spec(path: &Path, spec: &VmSpec) -> eyre::Result<()> {
    let config = serde_json::to_string_pretty(spec)
        .with_context(|| format!("serialize vm spec at {}", path.display()))?;
    std::fs::write(path, config).with_context(|| format!("write vm spec at {}", path.display()))
}

fn normalize_mount_sources(spec: &mut VmSpec, relative_mount_base: &Path) -> eyre::Result<()> {
    for mount in &mut spec.mounts {
        let resolved = resolve_mount_location(&mount.source)
            .map_err(eyre::Report::msg)
            .with_context(|| format!("resolve mount source {}", mount.source.display()))?;
        mount.source = if resolved.is_absolute() {
            resolved
        } else {
            relative_mount_base.join(resolved)
        };
    }

    Ok(())
}

fn prepare_default_initramfs(paths: &LocalPaths, spec: &mut VmSpec) -> eyre::Result<()> {
    if spec_initramfs(spec).is_some() {
        return Ok(());
    }

    let initramfs = paths.assets_dir().join(ASSET_INITRAMFS_FILENAME);
    require_asset(&initramfs, "guest initramfs")?;

    spec_kernel_mut(spec).initramfs = Some(initramfs);
    Ok(())
}

fn spec_initramfs(spec: &VmSpec) -> Option<&PathBuf> {
    spec.boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .and_then(|kernel| kernel.initramfs.as_ref())
}

fn spec_kernel_mut(spec: &mut VmSpec) -> &mut Kernel {
    let boot = spec.boot.get_or_insert(Boot {
        kernel: None,
        userdata: None,
    });
    boot.kernel.get_or_insert_with(|| Kernel {
        path: None,
        cmdline: Vec::new(),
        initramfs: None,
    })
}

fn require_asset(path: &Path, label: &str) -> eyre::Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        eyre::bail!(
            "missing boot asset: expected {label} at {}; build or copy it there before starting the VM",
            path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};

    use crate::paths::LocalPaths;
    use crate::vmmon::{prepare_launch_spec, LaunchSpecInput};

    use super::{normalize_mount_sources, prepare_default_initramfs, spec_kernel_mut};

    fn sample_spec(kernel_cmdline: Vec<String>) -> VmSpec {
        VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: None,
                    cmdline: kernel_cmdline,
                    initramfs: None,
                }),
                userdata: None,
            }),
            hardware: Some(Hardware {
                cpus: Some(4),
                memory: Some(4096),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            storage: Some(Storage { disks: Vec::new() }),
            mounts: Vec::new(),
            ..VmSpec::current()
        }
    }

    #[test]
    fn normalize_mount_sources_resolves_relative_sources_against_base() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![Mount {
            source: PathBuf::from("workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        }];

        normalize_mount_sources(&mut spec, Path::new("/tmp/project"))
            .expect("normalize runtime mounts");

        assert_eq!(
            spec.mounts[0].source,
            PathBuf::from("/tmp/project/workspace")
        );
    }

    #[test]
    fn normalize_mount_sources_preserves_absolute_sources() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![Mount {
            source: PathBuf::from("/workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        }];

        normalize_mount_sources(&mut spec, Path::new("/tmp/project"))
            .expect("normalize runtime mounts");

        assert_eq!(spec.mounts[0].source, PathBuf::from("/workspace"));
    }

    #[test]
    fn normalize_mount_sources_rejects_unsupported_tilde_forms() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![Mount {
            source: PathBuf::from("~somebody"),
            tag: "bad".to_string(),
            read_only: false,
        }];

        let err = normalize_mount_sources(&mut spec, Path::new("/tmp/project"))
            .expect_err("unsupported tilde form should fail");

        assert!(err
            .root_cause()
            .to_string()
            .contains("only '~' and '~/...'"));
    }

    #[test]
    fn runtime_initramfs_selects_default_static_asset() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        write_asset(&data_dir, "initramfs", b"initramfs");
        let mut spec = sample_spec(Vec::new());

        prepare_default_initramfs(&LocalPaths::new(&data_dir), &mut spec)
            .expect("prepare runtime initramfs");

        assert_eq!(
            spec.boot
                .as_ref()
                .and_then(|boot| boot.kernel.as_ref())
                .and_then(|kernel| kernel.initramfs.as_ref()),
            Some(data_dir.join("assets").join("initramfs")).as_ref()
        );
        assert!(spec.storage.as_ref().expect("storage").disks.is_empty());
    }

    #[test]
    fn runtime_initramfs_respects_explicit_initramfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let mut spec = sample_spec(Vec::new());
        spec_kernel_mut(&mut spec).initramfs = Some(PathBuf::from("custom-initramfs"));

        prepare_default_initramfs(&LocalPaths::new(&data_dir), &mut spec)
            .expect("explicit initramfs should be accepted");

        assert_eq!(
            spec.boot
                .as_ref()
                .and_then(|boot| boot.kernel.as_ref())
                .and_then(|kernel| kernel.initramfs.as_ref()),
            Some(&PathBuf::from("custom-initramfs"))
        );
    }

    #[test]
    fn prepare_launch_spec_returns_prepared_spec_by_value() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        write_asset(&data_dir, "initramfs", b"initramfs");
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![Mount {
            source: PathBuf::from("workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        }];

        let spec = prepare_launch_spec(LaunchSpecInput {
            paths: &LocalPaths::new(&data_dir),
            relative_mount_base: Path::new("/tmp/project"),
            spec,
        })
        .expect("prepare launch spec");

        assert_eq!(
            spec.mounts[0].source,
            PathBuf::from("/tmp/project/workspace")
        );
        assert_eq!(
            spec.boot
                .as_ref()
                .and_then(|boot| boot.kernel.as_ref())
                .and_then(|kernel| kernel.initramfs.as_ref()),
            Some(data_dir.join("assets").join("initramfs")).as_ref()
        );
    }

    fn write_asset(data_dir: &Path, name: &str, contents: &[u8]) {
        let assets_dir = data_dir.join("assets");
        fs::create_dir_all(&assets_dir).expect("create assets dir");
        fs::write(assets_dir.join(name), contents).expect("write asset");
    }
}

use std::path::Path;

use eyre::Context;
use vm_spec::VmSpec;

use crate::machine::resolve_mount_location;
use crate::runtime::normalize_absolute_path;

pub(crate) struct LaunchSpecInput<'a> {
    pub(crate) relative_mount_base: &'a Path,
    pub(crate) spec: VmSpec,
}

pub(crate) fn prepare_launch_spec(input: LaunchSpecInput<'_>) -> eyre::Result<VmSpec> {
    let mut spec = input.spec;
    normalize_mount_sources(&mut spec, input.relative_mount_base)?;
    Ok(spec)
}

/// Atomically publish the config and retain its exact inode for the launch barrier.
pub(crate) fn write_launch_spec(path: &Path, spec: &VmSpec) -> eyre::Result<std::fs::File> {
    use std::io::Write;

    let config = serde_json::to_vec_pretty(spec)
        .with_context(|| format!("serialize vm spec at {}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("launch spec has no parent"))?;
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| eyre::eyre!("launch spec has no UTF-8 name"))?;
    let directory = crate::paths::OwnedDirectory::open_existing_root(parent)?
        .ok_or_else(|| eyre::eyre!("launch directory disappeared"))?;
    directory
        .publish_file_deferred(
            name,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            |file| {
                file.write_all(&config)?;
                Ok(())
            },
        )
        .with_context(|| format!("publish vm spec at {}", path.display()))
}

fn normalize_mount_sources(spec: &mut VmSpec, relative_mount_base: &Path) -> eyre::Result<()> {
    for mount in &mut spec.mounts {
        let resolved = resolve_mount_location(&mount.source)
            .map_err(eyre::Report::msg)
            .with_context(|| format!("resolve mount source {}", mount.source.display()))?;
        let absolute = if resolved.is_absolute() {
            resolved
        } else {
            relative_mount_base.join(resolved)
        };
        mount.source = normalize_absolute_path(&absolute);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};

    use crate::supervisor::{prepare_launch_spec, LaunchSpecInput};

    use crate::supervisor::launch_spec::normalize_mount_sources;

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
    fn normalize_mount_sources_collapses_parent_components() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![Mount {
            source: PathBuf::from("../workspace/./src"),
            tag: "workspace".to_string(),
            read_only: false,
        }];

        normalize_mount_sources(&mut spec, Path::new("/tmp/project"))
            .expect("normalize runtime mounts");

        assert_eq!(spec.mounts[0].source, PathBuf::from("/tmp/workspace/src"));
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
    fn prepare_launch_spec_returns_prepared_spec_by_value() {
        let mut spec = sample_spec(Vec::new());
        spec.mounts = vec![Mount {
            source: PathBuf::from("workspace"),
            tag: "workspace".to_string(),
            read_only: false,
        }];

        let spec = prepare_launch_spec(LaunchSpecInput {
            relative_mount_base: Path::new("/tmp/project"),
            spec,
        })
        .expect("prepare launch spec");

        assert_eq!(
            spec.mounts[0].source,
            PathBuf::from("/tmp/project/workspace")
        );
    }
}

use std::fs;
use std::path::Path;

use agent_spec::{normalized_mount_plan, MountConfig, PlannedMount};
use eyre::{eyre, Context};

use crate::provision::{
    run_command, FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

pub(crate) struct Mounts<'a> {
    early_outcome: Option<&'a ProvisionOutcome>,
    mounts: &'a [MountConfig],
}

impl<'a> Mounts<'a> {
    pub(crate) fn with_early_outcome(
        mounts: &'a [MountConfig],
        outcome: Option<&'a ProvisionOutcome>,
    ) -> Self {
        Self {
            mounts,
            early_outcome: outcome,
        }
    }
}

pub(crate) fn validate_targets(
    context: &ProvisionContext,
    mounts: &[MountConfig],
) -> eyre::Result<()> {
    let plan = normalized_mount_plan(mounts)?;
    validate_plan_targets(context, &plan)
}

fn validate_plan_targets(
    context: &ProvisionContext,
    plan: &[PlannedMount<'_>],
) -> eyre::Result<()> {
    for mount in plan {
        validate_target(context, mount)?;
    }
    Ok(())
}

fn validate_target(context: &ProvisionContext, mount: &PlannedMount<'_>) -> eyre::Result<()> {
    validate_directory_ancestors(&context.guest_path(&mount.target))
        .with_context(|| format!("validate mount target {}", mount.target))
}

fn validate_directory_ancestors(target: &Path) -> eyre::Result<()> {
    for ancestor in target.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                eyre::bail!(
                    "mount target {} has a file or symlink ancestor {}",
                    target.display(),
                    ancestor.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect mount target {}", ancestor.display()))
            }
        }
    }
    Ok(())
}

pub(crate) fn prepare_early(
    context: &ProvisionContext,
    mounts: &[MountConfig],
    storage: &mut crate::root_storage::StorageShutdown,
) -> eyre::Result<ProvisionOutcome> {
    let plan = normalized_mount_plan(mounts)?;
    // No mkdir, unmount or mount happens until every target has been checked.
    validate_plan_targets(context, &plan)?;
    preflight_nested_sources(&plan)?;
    let mut changed = false;
    for mount in plan {
        validate_target(context, &mount)?;
        changed |= apply_mount(context, mount.config, &mount.target)
            .with_context(|| format!("required mount {} at {}", mount.config.tag, mount.target))?;
        storage
            .register_current(false)
            .context("retain mounted filesystem before admitting writes")?;
    }
    Ok(ProvisionOutcome::succeeded(changed))
}

fn parent_indexes(plan: &[PlannedMount<'_>]) -> Vec<Option<usize>> {
    let mut targets = std::collections::BTreeMap::new();
    let mut parents = Vec::with_capacity(plan.len());
    for (index, mount) in plan.iter().enumerate() {
        let mut path = mount.target.as_str();
        let mut parent = None;
        while let Some((prefix, _)) = path.rsplit_once('/') {
            if let Some(index) = targets.get(prefix) {
                parent = Some(*index);
                break;
            }
            path = prefix;
        }
        parents.push(parent);
        targets.insert(mount.target.as_str(), index);
    }
    parents
}

fn preflight_nested_sources(plan: &[PlannedMount<'_>]) -> eyre::Result<()> {
    let parents = parent_indexes(plan);
    if parents.iter().all(Option::is_none) {
        return Ok(());
    }
    // This runs before the Tokio runtime or supervisor threads exist. Staging
    // mounts are read-only in a child-only namespace, never at final targets.
    match unsafe { nix::unistd::fork() }.context("fork nested mount preflight")? {
        nix::unistd::ForkResult::Child => {
            let result = validate_nested_sources_in_namespace(plan, &parents);
            if let Err(error) = &result {
                tracing::error!(error = ?error, "required nested mount source preflight failed");
            }
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        nix::unistd::ForkResult::Parent { child } => loop {
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, 0)) => return Ok(()),
                Err(nix::errno::Errno::EINTR) => continue,
                Ok(status) => {
                    eyre::bail!("required nested mount source preflight failed: {status:?}")
                }
                Err(error) => return Err(error).context("wait for nested mount preflight"),
            }
        },
    }
}

fn validate_nested_sources_in_namespace(
    plan: &[PlannedMount<'_>],
    parents: &[Option<usize>],
) -> eyre::Result<()> {
    use nix::mount::{mount, MsFlags};
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .context("isolate mount preflight namespace")?;
    mount::<str, Path, str, str>(
        None,
        Path::new("/"),
        None,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None,
    )?;
    // /run already exists; all scratch mkdirs below are on this private tmpfs,
    // not on the guest root or the host shares being inspected.
    mount(
        Some("tmpfs"),
        Path::new("/run"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=0700,size=16M"),
    )?;
    let mut staged = vec![None; plan.len()];
    for (child, parent) in parents.iter().enumerate() {
        let Some(parent) = *parent else {
            continue;
        };
        let parent_mount = plan
            .get(parent)
            .ok_or_else(|| eyre!("nested mount parent index is invalid"))?;
        let child_mount = plan
            .get(child)
            .ok_or_else(|| eyre!("nested mount child index is invalid"))?;
        let staged_parent = staged
            .get_mut(parent)
            .ok_or_else(|| eyre!("nested staging index is invalid"))?;
        if staged_parent.is_none() {
            let path = std::path::PathBuf::from(format!("/run/share-{parent}"));
            fs::create_dir(&path)?;
            mount(
                Some(parent_mount.config.tag.as_str()),
                &path,
                Some("virtiofs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                None::<&str>,
            )
            .with_context(|| format!("stage read-only parent share {}", parent_mount.target))?;
            *staged_parent = Some(path);
        }
        let base = staged_parent
            .as_ref()
            .ok_or_else(|| eyre!("parent share staging missing"))?;
        let relative = child_mount
            .target
            .strip_prefix(&parent_mount.target)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or_else(|| eyre!("invalid nested mount relationship"))?;
        validate_directory_ancestors(&base.join(relative)).with_context(|| {
            format!(
                "validate nested target {} inside parent share {}",
                child_mount.target, parent_mount.target
            )
        })?;
    }
    Ok(())
}
impl<'a> Provisioner<'a> for Mounts<'a> {
    type Config = [MountConfig];

    fn init(config: &'a Self::Config) -> Self {
        Self {
            mounts: config,
            early_outcome: None,
        }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::MOUNTS
    }

    fn failure_policy(&self) -> FailurePolicy {
        FailurePolicy::FailBoot
    }

    fn apply(&self, _context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        if self.mounts.is_empty() {
            return Ok(ProvisionOutcome::skipped("no mounts configured"));
        }
        self.early_outcome
            .cloned()
            .ok_or_else(|| eyre!("required mounts were not prepared before init handoff"))
    }
}

fn apply_mount(
    context: &ProvisionContext,
    mount: &MountConfig,
    normalized_target: &str,
) -> eyre::Result<bool> {
    let target = context.guest_path(normalized_target);
    fs::create_dir_all(&target).with_context(|| format!("create {}", target.display()))?;
    if let Some(current) = current_mount(context, &target)? {
        if current.matches(mount) {
            tracing::debug!(path = %mount.path, tag = %mount.tag, "mount already reconciled");
            return Ok(false);
        }

        tracing::info!(
            path = %mount.path,
            current_source = %current.source,
            current_fstype = %current.fstype,
            current_options = %current.options,
            desired_tag = %mount.tag,
            desired_fstype = %mount.fstype,
            "remounting drifted mount target"
        );
        let target_arg = target
            .to_str()
            .ok_or_else(|| eyre!("mount target is not UTF-8"))?;
        run_command(context.process_supervisor(), "umount", ["--", target_arg])?;
    }

    let options = mount.options.join(",");
    let target_arg = target
        .to_str()
        .ok_or_else(|| eyre!("mount target is not UTF-8"))?;
    run_command(
        context.process_supervisor(),
        "mount",
        [
            "-t",
            mount.fstype.as_str(),
            "-o",
            options.as_str(),
            "--",
            mount.tag.as_str(),
            target_arg,
        ],
    )?;
    let observed = current_mount(context, &target)?.ok_or_else(|| {
        eyre!("required mount is absent after mount command: {normalized_target}")
    })?;
    if !observed.matches(mount) {
        eyre::bail!("required mount has wrong source, filesystem or access after mount: {normalized_target}");
    }
    tracing::info!(tag = %mount.tag, path = %mount.path, "reconciled mount");

    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
struct MountInfo {
    source: String,
    fstype: String,
    options: String,
}

impl MountInfo {
    fn matches(&self, mount: &MountConfig) -> bool {
        self.source == mount.tag
            && self.fstype == mount.fstype
            && read_only_option(&self.options)
                == mount
                    .options
                    .iter()
                    .any(|options| read_only_option(options))
            && mount.options.iter().all(|option| {
                !matches!(option.as_str(), "nosuid" | "nodev" | "noexec")
                    || self.options.split(',').any(|effective| effective == option)
            })
    }
}

fn current_mount(context: &ProvisionContext, path: &Path) -> eyre::Result<Option<MountInfo>> {
    let contents = fs::read_to_string(context.guest_path("/proc/self/mountinfo"))
        .context("read required mount state")?;
    parse_current_mount(&contents, path)
}

fn parse_current_mount(contents: &str, path: &Path) -> eyre::Result<Option<MountInfo>> {
    let mut found = None;
    for line in contents.lines() {
        let (mount, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| eyre!("malformed mountinfo"))?;
        let mut fields = mount.split_whitespace();
        let target = fields
            .nth(4)
            .ok_or_else(|| eyre!("mountinfo target missing"))?;
        let options = fields
            .next()
            .ok_or_else(|| eyre!("mountinfo access missing"))?;
        if crate::root_storage::decode_mount_path(target)? != path {
            continue;
        }
        if found.is_some() {
            eyre::bail!("stacked required mount target: {}", path.display());
        }
        let mut filesystem = filesystem.split_whitespace();
        let fstype = filesystem
            .next()
            .ok_or_else(|| eyre!("mountinfo filesystem missing"))?;
        let source = filesystem
            .next()
            .ok_or_else(|| eyre!("mountinfo source missing"))?;
        let source = crate::root_storage::decode_mount_path(source)?
            .into_os_string()
            .into_string()
            .map_err(|_| eyre!("mount source is not UTF-8"))?;
        found = Some(MountInfo {
            source,
            fstype: fstype.to_string(),
            options: options.to_string(),
        });
    }
    Ok(found)
}

fn read_only_option(options: &str) -> bool {
    options.split(',').any(|option| option == "ro")
}

#[cfg(test)]
mod tests {
    use agent_spec::MountConfig;

    use crate::provision::mounts::MountInfo;

    #[test]
    fn required_mountinfo_decodes_targets_and_sources_without_findmnt() {
        let contents = "42 1 0:99 / /workspace\\040dir ro,nosuid - virtiofs shared\\040tag ro\n";
        let mounted = crate::provision::mounts::parse_current_mount(
            contents,
            std::path::Path::new("/workspace dir"),
        )
        .expect("mountinfo")
        .expect("required mount");
        assert_eq!(mounted.source, "shared tag");
        assert_eq!(mounted.fstype, "virtiofs");
        assert_eq!(mounted.options, "ro,nosuid");
        assert!(crate::provision::mounts::parse_current_mount(
            contents,
            std::path::Path::new("/absent")
        )
        .expect("mountinfo")
        .is_none());
    }

    #[test]
    fn required_mountinfo_rejects_stacked_targets_and_malformed_rows() {
        let row = "42 1 0:99 / /workspace rw - virtiofs shared rw\n";
        assert!(crate::provision::mounts::parse_current_mount(
            &format!("{row}{row}"),
            std::path::Path::new("/workspace")
        )
        .is_err());
        assert!(crate::provision::mounts::parse_current_mount(
            "bad row",
            std::path::Path::new("/workspace")
        )
        .is_err());
    }

    fn directory_mount(tag: &str, path: &str) -> MountConfig {
        MountConfig {
            tag: tag.to_string(),
            path: path.to_string(),
            fstype: "virtiofs".to_string(),
            options: Vec::new(),
        }
    }

    #[test]
    fn nested_source_plan_uses_nearest_configured_parent() {
        let mounts = [
            directory_mount("child", "/parent/child/grandchild"),
            directory_mount("middle", "/parent/child"),
            directory_mount("parent", "/parent"),
        ];
        let plan = agent_spec::normalized_mount_plan(&mounts).unwrap();
        assert_eq!(
            crate::provision::mounts::parent_indexes(&plan),
            [None, Some(0), Some(1)]
        );
    }

    #[test]
    fn staged_parent_view_rejects_file_and_symlink_children_without_creating_targets() {
        let fixture = tempfile::tempdir().unwrap();
        let parent = fixture.path().join("read-only-parent-view");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("file"), b"parent share file").unwrap();
        std::os::unix::fs::symlink("/run/silo/rootfs", parent.join("alias")).unwrap();
        assert!(
            crate::provision::mounts::validate_directory_ancestors(&parent.join("file/child"))
                .is_err()
        );
        assert!(crate::provision::mounts::validate_directory_ancestors(
            &parent.join("alias/child")
        )
        .is_err());
        assert!(crate::provision::mounts::validate_directory_ancestors(
            &parent.join("absent/child")
        )
        .is_ok());
        assert!(!parent.join("absent").exists());
    }

    #[test]
    fn complete_plan_rejects_file_ancestor_before_creating_any_target() {
        let root = tempfile::tempdir().expect("fixture");
        std::fs::write(root.path().join("file"), b"not a directory").expect("file ancestor");
        let context = crate::provision::ProvisionContext::for_test(root.path());
        let mounts = [
            directory_mount("first", "/would-create"),
            directory_mount("second", "/file/child"),
        ];
        assert!(crate::provision::mounts::validate_targets(&context, &mounts).is_err());
        assert!(!root.path().join("would-create").exists());
    }

    #[test]
    fn complete_plan_rejects_symlink_into_root_maintenance() {
        let root = tempfile::tempdir().expect("fixture");
        std::fs::create_dir_all(root.path().join("run/silo/rootfs")).expect("maintenance");
        std::os::unix::fs::symlink(root.path().join("run/silo"), root.path().join("alias"))
            .expect("alias");
        let context = crate::provision::ProvisionContext::for_test(root.path());
        assert!(crate::provision::mounts::validate_targets(
            &context,
            &[directory_mount("a", "/alias/rootfs")]
        )
        .is_err());
    }

    #[test]
    fn configured_mount_without_early_completion_fails_boot() {
        use crate::provision::{FailurePolicy, Provisioner};
        let root = tempfile::tempdir().expect("fixture");
        let context = crate::provision::ProvisionContext::for_test(root.path());
        let mounts = [directory_mount("a", "/workspace")];
        let provisioner = crate::provision::mounts::Mounts::init(&mounts);
        assert_eq!(provisioner.failure_policy(), FailurePolicy::FailBoot);
        assert!(provisioner.apply(&context).is_err());
    }

    #[test]
    fn mount_info_matches_desired_source_type_and_read_only_state() {
        let desired = MountConfig {
            tag: "silo-home".to_string(),
            path: "/mnt/home".to_string(),
            fstype: "virtiofs".to_string(),
            options: vec!["ro".to_string(), "nofail".to_string()],
        };
        let current = MountInfo {
            source: "silo-home".to_string(),
            fstype: "virtiofs".to_string(),
            options: "ro,relatime".to_string(),
        };

        assert!(current.matches(&desired));
    }

    #[test]
    fn mount_info_rejects_different_read_only_state() {
        let desired = MountConfig {
            tag: "silo-home".to_string(),
            path: "/mnt/home".to_string(),
            fstype: "virtiofs".to_string(),
            options: vec!["rw".to_string(), "nofail".to_string()],
        };
        let current = MountInfo {
            source: "silo-home".to_string(),
            fstype: "virtiofs".to_string(),
            options: "ro,relatime".to_string(),
        };

        assert!(!current.matches(&desired));
    }
}

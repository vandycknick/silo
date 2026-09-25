use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use agent_spec::{AgentRosettaConfig, ROSETTA_INTERPRETER_PATH};
use eyre::Context;
use nix::errno::Errno;
use nix::mount::{mount, MsFlags};

use crate::provision::{
    FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const BINFMT_MISC_PATH: &str = "/proc/sys/fs/binfmt_misc";
const BINFMT_STATUS_PATH: &str = "/proc/sys/fs/binfmt_misc/status";
const ROSETTA_ENTRY_PATH: &str = "/proc/sys/fs/binfmt_misc/rosetta";
const BINFMT_REGISTER_PATH: &str = "/proc/sys/fs/binfmt_misc/register";
const ROSETTA_MAGIC_HEX: &str = "7f454c4602010100000000000000000002003e00";
const ROSETTA_MASK_HEX: &str = "fffffffffffefe00fffffffffffffffffeffffff";

// binfmt_misc parses registration as text. Raw NUL bytes terminate parsing, so
// non-printable magic and mask bytes must be ASCII escape sequences like `\x00`.
// Keep this as a raw byte string: the backslash-x text is intentional.
const ROSETTA_REGISTRATION_PREFIX: &[u8] = br":rosetta:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:";

// O passes an opened target fd, C preserves target credentials, and F pins the
// interpreter so x86 binaries continue to work in chroots and mount namespaces.
const ROSETTA_REGISTRATION_SUFFIX: &[u8] = b":OCF";

pub(crate) struct Rosetta<'a> {
    config: &'a AgentRosettaConfig,
    early_outcome: Option<&'a ProvisionOutcome>,
}

impl<'a> Rosetta<'a> {
    pub(crate) fn with_early_outcome(
        config: &'a AgentRosettaConfig,
        early_outcome: Option<&'a ProvisionOutcome>,
    ) -> Self {
        Self {
            config,
            early_outcome,
        }
    }
}

impl<'a> Provisioner<'a> for Rosetta<'a> {
    type Config = AgentRosettaConfig;

    fn init(config: &'a Self::Config) -> Self {
        Self::with_early_outcome(config, None)
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::ROSETTA
    }

    fn failure_policy(&self) -> FailurePolicy {
        if self.config.enabled {
            FailurePolicy::FailBoot
        } else {
            FailurePolicy::BestEffort
        }
    }

    fn apply(&self, _context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        if !self.config.enabled {
            return Ok(ProvisionOutcome::skipped("Rosetta disabled"));
        }

        self.early_outcome.cloned().ok_or_else(|| {
            eyre::eyre!("enabled Rosetta was not prepared during early guest bootstrap")
        })
    }
}

pub(crate) fn prepare_early(config: &AgentRosettaConfig) -> eyre::Result<Option<ProvisionOutcome>> {
    if !config.enabled {
        return Ok(None);
    }

    let mount_path = Path::new(&config.mount_path);
    let mount_changed = ensure_mount(
        &config.mount_tag,
        mount_path,
        "virtiofs",
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        &["ro", "nosuid", "nodev"],
    )
    .context("prepare Rosetta virtiofs mount")?;

    ensure_rosetta_binary(Path::new(ROSETTA_INTERPRETER_PATH))?;

    let binfmt_path = Path::new(BINFMT_MISC_PATH);
    let binfmt_changed = ensure_mount(
        "binfmt_misc",
        binfmt_path,
        "binfmt_misc",
        MsFlags::empty(),
        &[],
    )
    .context("prepare binfmt_misc mount")?;
    ensure_binfmt_enabled(Path::new(BINFMT_STATUS_PATH))?;
    let registration_changed = reconcile_registration(Path::new(ROSETTA_INTERPRETER_PATH))?;

    tracing::info!(
        mount_tag = %config.mount_tag,
        mount_path = %config.mount_path,
        rosetta = ROSETTA_INTERPRETER_PATH,
        "prepared required Rosetta bootstrap"
    );

    Ok(Some(ProvisionOutcome::succeeded(
        mount_changed || binfmt_changed || registration_changed,
    )))
}

fn ensure_mount(
    source: &str,
    target: &Path,
    fstype: &str,
    flags: MsFlags,
    required_options: &[&str],
) -> eyre::Result<bool> {
    ensure_mountpoint_directory(target)?;
    if let Some(current) = current_mount(target)? {
        current.ensure_matches(source, fstype, required_options, target)?;
        return Ok(false);
    }

    match mount(Some(source), target, Some(fstype), flags, None::<&str>) {
        Ok(()) => {}
        Err(Errno::EBUSY) => {}
        Err(err) => {
            return Err(eyre::eyre!(
                "mount {source:?} as {fstype} on {} failed: {err}",
                target.display()
            ));
        }
    }

    let mounted = current_mount(target)?.ok_or_else(|| {
        eyre::eyre!(
            "mount {source:?} on {} succeeded but mountinfo has no matching mount",
            target.display()
        )
    })?;
    mounted.ensure_matches(source, fstype, required_options, target)?;
    Ok(true)
}

fn ensure_mountpoint_directory(path: &Path) -> eyre::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => eyre::bail!("Rosetta mountpoint must be a directory: {}", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)
            .with_context(|| format!("create mountpoint {}", path.display())),
        Err(err) => Err(err).with_context(|| format!("stat mountpoint {}", path.display())),
    }
}

fn ensure_rosetta_binary(path: &Path) -> eyre::Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("open Rosetta binary {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened Rosetta binary {}", path.display()))?;
    if !metadata.is_file() {
        eyre::bail!("Rosetta binary is not a regular file: {}", path.display());
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        eyre::bail!("Rosetta binary is not executable: {}", path.display());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct MountInfo {
    root: String,
    source: String,
    fstype: String,
    mount_options: BTreeSet<String>,
    super_options: BTreeSet<String>,
}

impl MountInfo {
    fn ensure_matches(
        &self,
        source: &str,
        fstype: &str,
        required_options: &[&str],
        target: &Path,
    ) -> eyre::Result<()> {
        let missing = required_options
            .iter()
            .copied()
            .filter(|option| !self.mount_options.contains(*option))
            .collect::<Vec<_>>();
        let forbidden_noexec =
            required_options.contains(&"ro") && self.mount_options.contains("noexec");
        if self.root != "/"
            || self.source != source
            || self.fstype != fstype
            || !missing.is_empty()
            || forbidden_noexec
        {
            eyre::bail!(
                "conflicting mount at {}: root {:?}, source {:?}, type {:?}, mount options {:?}, super options {:?}; expected root \"/\", source {:?}, type {:?}, required mount options {:?}",
                target.display(),
                self.root,
                self.source,
                self.fstype,
                self.mount_options,
                self.super_options,
                source,
                fstype,
                required_options
            );
        }
        Ok(())
    }
}

fn current_mount(target: &Path) -> eyre::Result<Option<MountInfo>> {
    let contents = fs::read_to_string(MOUNTINFO_PATH).context("read /proc/self/mountinfo")?;
    parse_mountinfo(&contents, target)
}

fn parse_mountinfo(contents: &str, target: &Path) -> eyre::Result<Option<MountInfo>> {
    let mut matching = Vec::new();
    for line in contents.lines() {
        let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
            continue;
        };
        let fields = mount_fields.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || Path::new(&decode_mountinfo_field(fields[4])) != target {
            continue;
        }
        let filesystem_fields = filesystem_fields.split_whitespace().collect::<Vec<_>>();
        if filesystem_fields.len() < 3 {
            eyre::bail!("malformed mountinfo entry for {}", target.display());
        }
        let mount_options = fields[5].split(',').map(str::to_string).collect();
        let super_options = filesystem_fields[2]
            .split(',')
            .map(str::to_string)
            .collect();
        matching.push(MountInfo {
            root: decode_mountinfo_field(fields[3]),
            source: decode_mountinfo_field(filesystem_fields[1]),
            fstype: filesystem_fields[0].to_string(),
            mount_options,
            super_options,
        });
    }
    if matching.len() > 1 {
        eyre::bail!(
            "ambiguous stacked mounts at {}: found {} mountinfo entries",
            target.display(),
            matching.len()
        );
    }
    Ok(matching.pop())
}

fn decode_mountinfo_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn reconcile_registration(rosetta_binary: &Path) -> eyre::Result<bool> {
    let entry = Path::new(ROSETTA_ENTRY_PATH);
    if entry.exists() {
        ensure_registration_matches(entry, rosetta_binary)?;
        return Ok(false);
    }

    let register = Path::new(BINFMT_REGISTER_PATH);
    let registration = rosetta_registration(rosetta_binary);
    if let Err(write_error) = fs::write(register, &registration) {
        if entry.exists() {
            return ensure_registration_matches(entry, rosetta_binary)
                .with_context(|| format!("registration raced after write failed: {write_error}"))
                .map(|()| false);
        }
        return Err(write_error).with_context(|| {
            format!(
                "register Rosetta binfmt handler at {} using {} byte registration",
                register.display(),
                registration.len()
            )
        });
    }

    ensure_registration_matches(entry, rosetta_binary)?;
    Ok(true)
}

fn ensure_binfmt_enabled(status_path: &Path) -> eyre::Result<()> {
    let status = fs::read_to_string(status_path)
        .with_context(|| format!("read global binfmt_misc status {}", status_path.display()))?;
    match status.trim() {
        "enabled" => Ok(()),
        "disabled" => eyre::bail!(
            "global binfmt_misc is disabled at {}; refusing to mutate unrelated state",
            status_path.display()
        ),
        status => eyre::bail!(
            "unrecognized global binfmt_misc status {:?} at {}",
            status,
            status_path.display()
        ),
    }
}

fn ensure_registration_matches(entry: &Path, rosetta_binary: &Path) -> eyre::Result<()> {
    let contents = fs::read_to_string(entry)
        .with_context(|| format!("read Rosetta binfmt entry {}", entry.display()))?;
    let status = BinFmtEntryStatus::parse(&contents)?;
    let expected = BinFmtEntryStatus::expected(rosetta_binary);
    if status != expected {
        eyre::bail!(
            "conflicting Rosetta binfmt entry at {}: found {:?}, expected {:?}",
            entry.display(),
            status,
            expected
        );
    }
    Ok(())
}

fn rosetta_registration(rosetta_binary: &Path) -> Vec<u8> {
    let path = rosetta_binary.to_string_lossy();
    let mut registration = Vec::with_capacity(
        ROSETTA_REGISTRATION_PREFIX.len() + path.len() + ROSETTA_REGISTRATION_SUFFIX.len(),
    );
    registration.extend_from_slice(ROSETTA_REGISTRATION_PREFIX);
    registration.extend_from_slice(path.as_bytes());
    registration.extend_from_slice(ROSETTA_REGISTRATION_SUFFIX);
    registration
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BinFmtEntryStatus {
    enabled: Option<bool>,
    interpreter: Option<String>,
    flags: Option<String>,
    offset: Option<u64>,
    magic: Option<String>,
    mask: Option<String>,
}

impl BinFmtEntryStatus {
    fn expected(rosetta_binary: &Path) -> Self {
        Self {
            enabled: Some(true),
            interpreter: Some(rosetta_binary.display().to_string()),
            flags: Some(String::from("OCF")),
            offset: Some(0),
            magic: Some(String::from(ROSETTA_MAGIC_HEX)),
            mask: Some(String::from(ROSETTA_MASK_HEX)),
        }
    }

    fn parse(contents: &str) -> eyre::Result<Self> {
        let mut status = Self::default();
        for line in contents.lines().map(str::trim) {
            match line {
                "enabled" => status.enabled = Some(true),
                "disabled" => status.enabled = Some(false),
                _ => {
                    if let Some((name, value)) =
                        line.split_once(' ').or_else(|| line.split_once(':'))
                    {
                        let value = value.trim();
                        match name.trim_end_matches(':') {
                            "interpreter" => status.interpreter = Some(value.to_string()),
                            "flags" => status.flags = Some(value.to_string()),
                            "offset" => {
                                status.offset =
                                    Some(value.parse().with_context(|| {
                                        format!("parse binfmt offset {value:?}")
                                    })?)
                            }
                            "magic" => status.magic = Some(value.to_ascii_lowercase()),
                            "mask" => status.mask = Some(value.to_ascii_lowercase()),
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use agent_spec::ROSETTA_INTERPRETER_PATH;

    use crate::provision::rosetta::{
        ensure_binfmt_enabled, ensure_registration_matches, parse_mountinfo, rosetta_registration,
        BinFmtEntryStatus, Rosetta, ROSETTA_MASK_HEX, ROSETTA_REGISTRATION_PREFIX,
        ROSETTA_REGISTRATION_SUFFIX,
    };
    use crate::provision::{FailurePolicy, ProvisionContext, ProvisionOutcome, Provisioner};

    const MATCHING_ENTRY: &str = "enabled\ninterpreter /mnt/rosetta/rosetta\nflags: OCF\noffset 0\nmagic 7f454c4602010100000000000000000002003e00\nmask fffffffffffefe00fffffffffffffffffeffffff\n";

    #[test]
    fn registration_uses_configured_rosetta_path_and_ocf_flags() {
        let registration = rosetta_registration(Path::new(ROSETTA_INTERPRETER_PATH));

        assert!(registration.starts_with(ROSETTA_REGISTRATION_PREFIX));
        assert!(registration.ends_with(ROSETTA_REGISTRATION_SUFFIX));
        assert!(!registration.contains(&0));
        assert!(registration
            .windows(ROSETTA_INTERPRETER_PATH.len())
            .any(|window| window == ROSETTA_INTERPRETER_PATH.as_bytes()));
        assert!(registration
            .windows(br"\x00".len())
            .any(|window| window == br"\x00"));
    }

    #[test]
    fn parses_complete_registered_binfmt_entry_status() {
        let status = BinFmtEntryStatus::parse(MATCHING_ENTRY).expect("parse binfmt entry");

        assert_eq!(
            status,
            BinFmtEntryStatus::expected(Path::new(ROSETTA_INTERPRETER_PATH))
        );
        assert_eq!(status.mask.as_deref(), Some(ROSETTA_MASK_HEX));
    }

    #[test]
    fn identical_registration_validation_does_not_write_it() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let entry = dir.path().join("rosetta");
        fs::write(&entry, MATCHING_ENTRY).expect("write entry fixture");
        let before = fs::read(&entry).expect("read entry before reconciliation");

        ensure_registration_matches(&entry, Path::new(ROSETTA_INTERPRETER_PATH))
            .expect("matching registration");

        assert_eq!(fs::read(entry).expect("read entry afterward"), before);
    }

    #[test]
    fn conflicting_registration_validation_does_not_write_it() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let entry = dir.path().join("rosetta");
        let conflict = MATCHING_ENTRY.replace("flags: OCF", "flags: F");
        fs::write(&entry, &conflict).expect("write conflicting entry fixture");

        let error = ensure_registration_matches(&entry, Path::new(ROSETTA_INTERPRETER_PATH))
            .expect_err("reject conflicting registration");

        assert!(error
            .to_string()
            .contains("conflicting Rosetta binfmt entry"));
        assert_eq!(
            fs::read_to_string(entry).expect("read entry afterward"),
            conflict
        );
    }

    #[test]
    fn mountinfo_requires_owned_executable_mount_identity() {
        let contents = "31 23 0:28 / /mnt/rosetta ro,nosuid,nodev,relatime - virtiofs rosetta ro\n";
        let mount = parse_mountinfo(contents, Path::new("/mnt/rosetta"))
            .expect("parse mountinfo")
            .expect("Rosetta mount");

        mount
            .ensure_matches(
                "rosetta",
                "virtiofs",
                &["ro", "nosuid", "nodev"],
                Path::new("/mnt/rosetta"),
            )
            .expect("matching owned mount");
        assert!(!mount.mount_options.contains("noexec"));
    }

    #[test]
    fn mountinfo_rejects_conflicts_using_per_mount_options() {
        for contents in [
            "31 23 0:28 / /mnt/rosetta ro,nosuid,nodev - virtiofs somebody-else ro\n",
            "31 23 0:28 / /mnt/rosetta ro,nosuid,nodev,noexec - virtiofs rosetta ro\n",
            "31 23 0:28 / /mnt/rosetta rw,nosuid,nodev - virtiofs rosetta ro\n",
            "31 23 0:28 /subdir /mnt/rosetta ro,nosuid,nodev - virtiofs rosetta ro\n",
        ] {
            let mount = parse_mountinfo(contents, Path::new("/mnt/rosetta"))
                .expect("parse mountinfo")
                .expect("Rosetta mount");
            assert!(mount
                .ensure_matches(
                    "rosetta",
                    "virtiofs",
                    &["ro", "nosuid", "nodev"],
                    Path::new("/mnt/rosetta")
                )
                .is_err());
        }
    }

    #[test]
    fn mountinfo_rejects_ambiguous_stacked_mountpoint_entries() {
        let contents = "31 23 0:28 / /mnt/rosetta ro,nosuid,nodev - virtiofs rosetta ro\n32 23 0:29 / /mnt/rosetta ro,nosuid,nodev - virtiofs rosetta ro\n";

        let error = parse_mountinfo(contents, Path::new("/mnt/rosetta"))
            .expect_err("reject stacked mountpoint entries");

        assert!(error.to_string().contains("ambiguous stacked mounts"));
    }

    #[test]
    fn global_binfmt_status_must_be_enabled_without_mutation() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let status_path = dir.path().join("status");
        fs::write(&status_path, "enabled\n").expect("write enabled status");
        let before = fs::read(&status_path).expect("read status before validation");

        ensure_binfmt_enabled(&status_path).expect("enabled global binfmt status");

        assert_eq!(
            fs::read(&status_path).expect("read status afterward"),
            before
        );
    }

    #[test]
    fn disabled_global_binfmt_status_fails_without_mutation() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let status_path = dir.path().join("status");
        fs::write(&status_path, "disabled\n").expect("write disabled status");
        let before = fs::read(&status_path).expect("read status before validation");

        let error = ensure_binfmt_enabled(&status_path).expect_err("reject disabled global status");

        assert!(error.to_string().contains("global binfmt_misc is disabled"));
        assert_eq!(
            fs::read(&status_path).expect("read status afterward"),
            before
        );
    }

    #[test]
    fn enabled_rosetta_is_fail_boot_but_disabled_rosetta_stays_best_effort() {
        let mut config = agent_spec::AgentRosettaConfig::default();
        assert_eq!(
            Rosetta::init(&config).failure_policy(),
            FailurePolicy::BestEffort
        );

        config.enabled = true;
        assert_eq!(
            Rosetta::init(&config).failure_policy(),
            FailurePolicy::FailBoot
        );
    }

    #[test]
    fn provisioning_report_uses_the_early_bootstrap_outcome() {
        let config = agent_spec::AgentRosettaConfig {
            enabled: true,
            ..agent_spec::AgentRosettaConfig::default()
        };
        let early = ProvisionOutcome::succeeded(true);
        let context = ProvisionContext::for_test(Path::new("/unused"));

        let outcome = Rosetta::with_early_outcome(&config, Some(&early))
            .apply(&context)
            .expect("reuse early bootstrap outcome");

        assert_eq!(outcome, early);
        assert!(Rosetta::with_early_outcome(&config, None)
            .apply(&context)
            .expect_err("missing early bootstrap must fail")
            .to_string()
            .contains("not prepared during early guest bootstrap"));
    }
}

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use agent_spec::AgentRosettaConfig;
use eyre::Context;

use crate::provision::{command_exists, command_status, run_command, ProvisionContext};

const BINFMT_MISC_PATH: &str = "/proc/sys/fs/binfmt_misc";
const ROSETTA_ENTRY_PATH: &str = "/proc/sys/fs/binfmt_misc/rosetta";
const BINFMT_REGISTER_PATH: &str = "/proc/sys/fs/binfmt_misc/register";

// binfmt_misc parses registration as text. Raw NUL bytes terminate parsing, so
// non-printable magic and mask bytes must be ASCII escape sequences like `\x00`.
// Keep this as a raw byte string: the backslash-x text is intentional.
const ROSETTA_REGISTRATION_PREFIX: &[u8] = br":rosetta:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:";

// binfmt_misc supports P, O, C, and F flags:
// - P preserves argv[0]. Rosetta does not need Silo to alter argv handling.
// - O opens the target binary and passes the fd to the interpreter.
// - C uses target-binary credentials and implies O; this matches normal exec semantics.
// - F opens and pins the interpreter at registration time. Docker containers,
//   chroots, and mount namespaces may not have /mnt/silo-rosetta mounted, so
//   Rosetta needs F even though it can keep the virtiofs mount busy until the
//   binfmt entry is unregistered.
const ROSETTA_REGISTRATION_SUFFIX: &[u8] = b":OCF";

pub(crate) fn apply(context: &ProvisionContext, config: &AgentRosettaConfig) -> eyre::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let mount_path = context.guest_path(&config.mount_path);
    fs::create_dir_all(&mount_path)
        .with_context(|| format!("create Rosetta mount path {}", mount_path.display()))?;
    mount_if_needed(
        context,
        &mount_path,
        ["-t", "virtiofs", config.mount_tag.as_str()],
    )?;

    let rosetta_binary = mount_path.join("rosetta");
    ensure_rosetta_binary(&rosetta_binary)?;

    let binfmt_path = context.guest_path(BINFMT_MISC_PATH);
    fs::create_dir_all(&binfmt_path)
        .with_context(|| format!("create binfmt_misc path {}", binfmt_path.display()))?;
    mount_if_needed(context, &binfmt_path, ["-t", "binfmt_misc", "binfmt_misc"])?;

    unregister_existing_rosetta(context)?;
    register_rosetta(context, &rosetta_binary)?;
    log_registered_rosetta(context)?;

    tracing::info!(
        mount_tag = %config.mount_tag,
        mount_path = %config.mount_path,
        rosetta = %rosetta_binary.display(),
        "reconciled Rosetta binfmt handler"
    );

    Ok(())
}

fn mount_if_needed<const N: usize>(
    context: &ProvisionContext,
    target: &Path,
    args: [&str; N],
) -> eyre::Result<()> {
    if is_mounted(context, target) {
        tracing::debug!(path = %target.display(), "mount target already mounted");
        return Ok(());
    }

    let target = target.to_string_lossy().to_string();
    let mut command_args = Vec::with_capacity(N + 1);
    command_args.extend(args);
    command_args.push(target.as_str());
    run_command(context.process_supervisor(), "mount", command_args)
}

fn is_mounted(context: &ProvisionContext, path: &Path) -> bool {
    if !command_exists("findmnt") {
        return false;
    }

    let path = path.to_string_lossy().to_string();
    command_status(
        context.process_supervisor(),
        "findmnt",
        ["--mountpoint", path.as_str()],
    )
    .map(|status| status.success())
    .unwrap_or(false)
}

fn ensure_rosetta_binary(path: &Path) -> eyre::Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("stat Rosetta binary {}", path.display()))?;
    if !metadata.is_file() {
        eyre::bail!("Rosetta binary is not a file: {}", path.display());
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        eyre::bail!("Rosetta binary is not executable: {}", path.display());
    }
    Ok(())
}

fn unregister_existing_rosetta(context: &ProvisionContext) -> eyre::Result<()> {
    let entry = context.guest_path(ROSETTA_ENTRY_PATH);
    if !entry.exists() {
        return Ok(());
    }

    fs::write(&entry, b"-1").with_context(|| {
        format!(
            "unregister existing Rosetta binfmt entry {}",
            entry.display()
        )
    })
}

fn register_rosetta(context: &ProvisionContext, rosetta_binary: &Path) -> eyre::Result<()> {
    let register = context.guest_path(BINFMT_REGISTER_PATH);
    let registration = rosetta_registration(rosetta_binary);
    let registration_len = registration.len();
    fs::write(&register, registration).with_context(|| {
        format!(
            "register Rosetta binfmt handler at {} using {} byte registration for {}",
            register.display(),
            registration_len,
            rosetta_binary.display()
        )
    })
}

fn log_registered_rosetta(context: &ProvisionContext) -> eyre::Result<()> {
    let entry = context.guest_path(ROSETTA_ENTRY_PATH);
    let contents = fs::read_to_string(&entry)
        .with_context(|| format!("read registered Rosetta binfmt entry {}", entry.display()))?;
    let status = BinFmtEntryStatus::parse(&contents);
    tracing::debug!(
        enabled = ?status.enabled,
        interpreter = ?status.interpreter.as_deref(),
        flags = ?status.flags.as_deref(),
        "registered Rosetta binfmt entry"
    );
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
}

impl BinFmtEntryStatus {
    fn parse(contents: &str) -> Self {
        let mut status = Self::default();
        for line in contents.lines().map(str::trim) {
            match line {
                "enabled" => status.enabled = Some(true),
                "disabled" => status.enabled = Some(false),
                _ => {
                    if let Some(interpreter) = line
                        .strip_prefix("interpreter ")
                        .or_else(|| line.strip_prefix("interpreter:"))
                    {
                        status.interpreter = Some(interpreter.trim().to_string());
                    } else if let Some(flags) = line
                        .strip_prefix("flags ")
                        .or_else(|| line.strip_prefix("flags:"))
                    {
                        status.flags = Some(flags.trim().to_string());
                    }
                }
            }
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn registration_uses_configured_rosetta_path() {
        let registration = super::rosetta_registration(Path::new("/mnt/rosetta/rosetta"));

        assert!(registration.starts_with(super::ROSETTA_REGISTRATION_PREFIX));
        assert!(registration.ends_with(super::ROSETTA_REGISTRATION_SUFFIX));
        assert!(!registration.contains(&0));
        assert!(registration
            .windows(b"/mnt/rosetta/rosetta".len())
            .any(|window| window == b"/mnt/rosetta/rosetta"));
    }

    #[test]
    fn registration_uses_escaped_magic_and_ocf_flags() {
        let registration = super::rosetta_registration(Path::new("/mnt/rosetta/rosetta"));

        assert!(registration
            .windows(br"\x00".len())
            .any(|window| window == br"\x00"));
        assert!(registration.ends_with(b":OCF"));
    }

    #[test]
    fn parses_registered_binfmt_entry_status() {
        let status = super::BinFmtEntryStatus::parse(
            "enabled\ninterpreter /mnt/silo-rosetta/rosetta\nflags: OCF\n",
        );

        assert_eq!(status.enabled, Some(true));
        assert_eq!(
            status.interpreter.as_deref(),
            Some("/mnt/silo-rosetta/rosetta")
        );
        assert_eq!(status.flags.as_deref(), Some("OCF"));
    }
}

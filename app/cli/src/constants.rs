/// Clap help template used for every command and subcommand.
///
/// The template keeps Bento's CLI help compact while preserving clap's normal
/// usage and argument sections. In particular, examples are rendered directly
/// after `Usage:` by each command's `after_help` text.
pub(crate) const HELP_TEMPLATE: &str =
    "{about-section}\n{usage-heading} {usage}{after-help}\n{all-args}";

/// Profile name used when `bento run` is invoked without an explicit profile.
///
/// The profile store first looks for this name on disk, then falls back to the
/// built-in profile definition.
pub(crate) const DEFAULT_PROFILE_NAME: &str = "default";

/// Image reference used by the built-in default profile.
///
/// This is intentionally a CLI/profile default, not a libvm default. libvm only
/// creates machines from the image reference the caller passes in.
pub(crate) const DEFAULT_PROFILE_IMAGE: &str = "ghcr.io/vandycknick/archlinux:latest";

/// Internal machine metadata key recording which Bento profile created a VM.
///
/// This is stored in libvm's opaque `metadata` map so libvm does not need to
/// know what a profile is. It is not a user-facing label and should not be set
/// through `--label`.
pub(crate) const PROFILE_METADATA_KEY: &str = "bento.profile";

/// Private SSH key filename used for Bento guest login credentials.
pub(crate) const GUEST_SSH_PRIVATE_KEY_FILE_NAME: &str = "id_ed25519";

/// Public SSH key filename used for Bento guest login credentials.
pub(crate) const GUEST_SSH_PUBLIC_KEY_FILE_NAME: &str = "id_ed25519.pub";

//! Shared constants for libvm behavior that crosses module boundaries.

/// Static initramfs asset filename under the local Bento assets directory.
pub(crate) const ASSET_INITRAMFS_FILENAME: &str = "initramfs";

/// Local certificate authority certificate filename under the Bento keys directory.
pub(crate) const CERTIFICATE_AUTHORITY_CERTIFICATE_FILE_NAME: &str = "ca.pem";

/// Local certificate authority private key filename under the Bento keys directory.
pub(crate) const CERTIFICATE_AUTHORITY_PRIVATE_KEY_FILE_NAME: &str = "ca-key.pem";

/// Common name used for the generated local Bento certificate authority.
pub(crate) const CERTIFICATE_AUTHORITY_COMMON_NAME: &str = "Bento Local Certificate Authority";

/// Host path checked for the system localtime symlink.
pub(crate) const HOST_LOCALTIME_PATH: &str = "/etc/localtime";

/// Host path checked for Debian-style timezone configuration.
pub(crate) const HOST_TIMEZONE_PATH: &str = "/etc/timezone";

/// Timezone used when no host timezone signal is available.
pub(crate) const DEFAULT_HOST_TIMEZONE: &str = "UTC";

/// Locale used when no host locale environment variable is available.
pub(crate) const DEFAULT_HOST_LOCALE: &str = "en_US.UTF-8";

/// Vsock endpoint name reserved for the guest forward service.
pub(crate) const FORWARD_ENDPOINT_NAME: &str = "forward";

/// Certificate authority path installed inside the guest for provisioning trust.
pub(crate) const GUEST_CERTIFICATE_AUTHORITY_PATH: &str =
    "/usr/local/share/ca-certificates/bento-ca.crt";

/// Private SSH key filename used for Bento guest login credentials.
pub(crate) const GUEST_SSH_PRIVATE_KEY_FILE_NAME: &str = "id_ed25519";

/// Public SSH key filename used for Bento guest login credentials.
pub(crate) const GUEST_SSH_PUBLIC_KEY_FILE_NAME: &str = "id_ed25519.pub";

/// Default shell assigned to the provisioned guest user.
pub(crate) const GUEST_USER_SHELL: &str = "/bin/bash";

/// Sudo policy assigned to the provisioned guest user.
pub(crate) const GUEST_USER_SUDO_RULE: &str = "ALL=(ALL) NOPASSWD:ALL";

/// Driver match used by the guest agent for Virtualization.framework NAT interfaces.
pub(crate) const VZNAT_MATCH_DRIVER: &str = "virtio_net";

/// Guest network interface name used for Virtualization.framework NAT networking.
pub(crate) const VZNAT_INTERFACE_NAME: &str = "en";

/// Guest network interface name used for Bento unix datagram networking.
pub(crate) const UNIX_DATAGRAM_INTERFACE_NAME: &str = "bento";

/// Filesystem type reported to the guest agent for virtiofs mounts.
pub(crate) const VIRTIOFS_FSTYPE: &str = "virtiofs";

/// Read-only mount option reported to the guest agent.
pub(crate) const MOUNT_OPTION_READ_ONLY: &str = "ro";

/// Read-write mount option reported to the guest agent.
pub(crate) const MOUNT_OPTION_READ_WRITE: &str = "rw";

/// Optional mount option reported to the guest agent so missing mounts do not fail boot.
pub(crate) const MOUNT_OPTION_NOFAIL: &str = "nofail";

/// Userdata content type marker for cloud-config input.
pub(crate) const USERDATA_CONTENT_TYPE_CLOUD_CONFIG: &str = "text/cloud-config";

/// Userdata content type marker for shell-script input.
pub(crate) const USERDATA_CONTENT_TYPE_SHELL_SCRIPT: &str = "text/x-shellscript";

/// Userdata content type marker for plain text input.
pub(crate) const USERDATA_CONTENT_TYPE_PLAIN_TEXT: &str = "text/plain";

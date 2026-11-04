//! Immutable managed-root boot admission. Artifact metadata describes candidates;
//! only an observed exact boot tuple in this module can admit a production boot.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use rootfs_spec::{OverlayProfile, OverlayRenderingAbi, UpperProfile};
use sha2::{Digest, Sha256};
use thiserror::Error;
use vm_spec::live::LiveBackend;

use crate::GuestArchitecture;

const ROOT_PROFILE: &str = "linux-flat-overlay-v1";
const ATTACHMENT_FAMILY: &str = "krun-virtio-blk-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootIdentity {
    kernel_sha256: [u8; 32],
    initramfs_sha256: [u8; 32],
    native_sha256: [u8; 32],
    architecture: GuestArchitecture,
}

#[derive(Clone, Copy, Debug)]
struct AdmittedBoot {
    identity: BootIdentity,
    resolved_config_sha256: [u8; 32],
    kernel_version: (u32, u32, u32),
    host_os: &'static str,
    host_arch: &'static str,
    root_profile: &'static str,
    upper_profile: UpperProfile,
    overlay_profile: OverlayProfile,
    rendering_abi: OverlayRenderingAbi,
    attachment_family: &'static str,
    evidence: &'static str,
}

// Only reviewed real monitor/worker observations admit exact tuples. This
// candidate binds the corrected native image; it is not evidence that the
// subsequent normal libvm integration/conformance matrix has passed.
const ADMITTED_BOOTS: &[AdmittedBoot] = &[AdmittedBoot {
    identity: BootIdentity {
        kernel_sha256: [
            0xec, 0x6f, 0xee, 0x8b, 0x18, 0x85, 0xa7, 0x1e, 0x78, 0x30, 0x6f, 0xea, 0x38, 0x4f,
            0x4f, 0xf6, 0x68, 0x7f, 0xd1, 0x51, 0xb6, 0xf2, 0x79, 0xc2, 0x31, 0x17, 0x78, 0x50,
            0x27, 0x74, 0x8f, 0x33,
        ],
        initramfs_sha256: [
            0x63, 0x2d, 0x14, 0xf7, 0xea, 0x50, 0xee, 0x01, 0x8a, 0x5e, 0x7a, 0x78, 0xf5, 0x0a,
            0x27, 0xfb, 0xda, 0xc2, 0xbb, 0x16, 0x35, 0x89, 0xec, 0x56, 0xe2, 0xe9, 0x28, 0xb3,
            0x6e, 0x70, 0x15, 0xb8,
        ],
        native_sha256: [
            0x95, 0x6e, 0x4d, 0x61, 0x3b, 0xa0, 0xb2, 0x11, 0xe0, 0xe7, 0xf8, 0xda, 0x59, 0xb7,
            0x12, 0x5b, 0xb8, 0x2c, 0xb0, 0xe4, 0xe1, 0x5e, 0x1b, 0x52, 0x45, 0xcf, 0xb0, 0x56,
            0x38, 0xb8, 0x60, 0x24,
        ],
        architecture: GuestArchitecture::Amd64,
    },
    resolved_config_sha256: [
        0xf3, 0xda, 0xb6, 0xad, 0xff, 0xce, 0x7c, 0xad, 0xde, 0x5c, 0xe6, 0x93, 0xf9, 0x40, 0x3c,
        0xe8, 0x8d, 0x66, 0xab, 0x9f, 0x4e, 0xc5, 0x03, 0xf7, 0x86, 0x0c, 0xe9, 0x02, 0x0c, 0xb1,
        0x42, 0xe6,
    ],
    kernel_version: (7, 2, 2),
    host_os: "linux",
    host_arch: "x86_64",
    root_profile: ROOT_PROFILE,
    upper_profile: UpperProfile::SiloUpperExt4V1,
    overlay_profile: OverlayProfile::SiloOverlayV1,
    rendering_abi: OverlayRenderingAbi::LinuxOverlayfsMountinfoV1,
    attachment_family: ATTACHMENT_FAMILY,
    evidence: "resources/kernels/artifacts.md#observed-linux-kvm-candidate",
}];

/// Owns qualified sources through launch. Guest assets are staged through checked
/// copies; Linux executes the retained native descriptor without reopening paths.
#[derive(Debug)]
pub struct QualifiedOverlayBoot {
    admitted: AdmittedBoot,
    kernel: QualifiedAsset,
    initramfs: QualifiedAsset,
    native: QualifiedAsset,
}

impl QualifiedOverlayBoot {
    pub fn rendering_abi(&self) -> OverlayRenderingAbi {
        self.admitted.rendering_abi
    }

    pub fn upper_profile(&self) -> UpperProfile {
        self.admitted.upper_profile
    }

    pub fn overlay_profile(&self) -> OverlayProfile {
        self.admitted.overlay_profile
    }

    pub fn resolved_config_sha256(&self) -> [u8; 32] {
        self.admitted.resolved_config_sha256
    }

    pub fn evidence(&self) -> &'static str {
        self.admitted.evidence
    }

    /// Append the exact qualified base to a private composite temporary. The
    /// root/agent archive is added only after this checked copy succeeds.
    pub(crate) fn copy_initramfs(
        &self,
        output: &mut impl Write,
    ) -> Result<u64, OverlayBootQualificationError> {
        self.initramfs.copy_into(output)
    }

    pub(crate) fn kernel_asset(&self) -> &QualifiedAsset {
        &self.kernel
    }

    pub(crate) fn initramfs_asset(&self) -> &QualifiedAsset {
        &self.initramfs
    }

    pub(crate) fn into_boot_assets(self) -> (QualifiedAsset, QualifiedAsset) {
        (self.kernel, self.initramfs)
    }

    /// The actual qualified monitor/worker image, retained CLOEXEC and >=3.
    /// Its owner must stay alive until the monitor has been spawned. Do not clear
    /// CLOEXEC in the parent; Linux resolves /proc/self/fd/N before closing it.
    pub(crate) fn native_executable_fd(&self) -> BorrowedFd<'_> {
        self.native.file.as_fd()
    }

    /// Check immediately before descriptor-based spawn. This protects cooperative
    /// atomic publication, not hostile same-UID in-place executable mutation.
    pub(crate) fn recheck_native_executable(&self) -> Result<(), OverlayBootQualificationError> {
        self.native.recheck()
    }
}

#[derive(Debug, Error)]
pub enum OverlayBootQualificationError {
    #[error("failed to read managed-overlay boot asset {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("managed-overlay boot asset is not a nonempty regular file: {path}")]
    InvalidAsset { path: PathBuf },
    #[error("managed-overlay boot asset changed during qualification or launch copying: {path}")]
    AssetChanged { path: PathBuf },
    #[error("failed to copy qualified managed-overlay boot asset {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "managed-overlay boot qualification requires the actual krun backend, got {backend:?}"
    )]
    UnsupportedBackend { backend: LiveBackend },
    #[error("managed-overlay native descriptor launch is not qualified on host {host_os}")]
    UnsupportedHost { host_os: &'static str },
    #[error("managed-overlay native image is not executable: {path}")]
    InvalidExecutable { path: PathBuf },
    #[error("{identity}")]
    Unqualified {
        identity: Box<UnqualifiedOverlayBootIdentity>,
    },
}

/// Cold diagnostic identity for a rejected exact tuple. Keeping it boxed avoids
/// enlarging every successful libvm Result while preserving typed failure data.
#[derive(Debug, Error)]
#[error("unqualified {profile} boot tuple: kernel sha256:{kernel_sha256}, base initramfs sha256:{initramfs_sha256}, native sha256:{native_sha256}, guest {architecture:?}, host {host_os}/{host_arch}; exact real monitor/worker qualification is required")]
pub struct UnqualifiedOverlayBootIdentity {
    pub profile: &'static str,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
    pub native_sha256: String,
    pub architecture: GuestArchitecture,
    pub host_os: &'static str,
    pub host_arch: &'static str,
}

/// Admit reusable kernel/base-initramfs bytes before any machine or storage
/// effects. The per-launch root/agent archive must be appended only afterwards.
/// Config identity is bound by the reviewed tuple's exact kernel digest, not by
/// a caller-supplied or mutable metadata claim.
pub fn admit_flat_overlay(
    kernel: &Path,
    initramfs: &Path,
    architecture: GuestArchitecture,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<QualifiedOverlayBoot, OverlayBootQualificationError> {
    if backend != LiveBackend::Krun {
        return Err(OverlayBootQualificationError::UnsupportedBackend { backend });
    }
    if !cfg!(target_os = "linux") {
        return Err(OverlayBootQualificationError::UnsupportedHost {
            host_os: std::env::consts::OS,
        });
    }
    admit_flat_overlay_assets(
        QualifiedAsset::open(kernel)?,
        QualifiedAsset::open(initramfs)?,
        architecture,
        backend,
        native_executable,
    )
}

/// Qualify the already authenticated held guest assets, never their former paths.
pub(crate) fn admit_flat_overlay_assets(
    kernel: QualifiedAsset,
    initramfs: QualifiedAsset,
    architecture: GuestArchitecture,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<QualifiedOverlayBoot, OverlayBootQualificationError> {
    if backend != LiveBackend::Krun {
        return Err(OverlayBootQualificationError::UnsupportedBackend { backend });
    }
    if !cfg!(target_os = "linux") {
        return Err(OverlayBootQualificationError::UnsupportedHost {
            host_os: std::env::consts::OS,
        });
    }
    let native = QualifiedAsset::open_executable(native_executable)?;
    let identity = BootIdentity {
        kernel_sha256: kernel.digest,
        initramfs_sha256: initramfs.digest,
        native_sha256: native.digest,
        architecture,
    };
    match admitted_boot(
        identity,
        std::env::consts::OS,
        std::env::consts::ARCH,
        ADMITTED_BOOTS,
    ) {
        Some(admitted) => Ok(QualifiedOverlayBoot {
            admitted,
            kernel,
            initramfs,
            native,
        }),
        None => Err(OverlayBootQualificationError::Unqualified {
            identity: Box::new(UnqualifiedOverlayBootIdentity {
                profile: ROOT_PROFILE,
                kernel_sha256: hex_digest(identity.kernel_sha256),
                initramfs_sha256: hex_digest(identity.initramfs_sha256),
                native_sha256: hex_digest(identity.native_sha256),
                architecture,
                host_os: std::env::consts::OS,
                host_arch: std::env::consts::ARCH,
            }),
        }),
    }
}

fn admitted_boot(
    identity: BootIdentity,
    host_os: &str,
    host_arch: &str,
    entries: &[AdmittedBoot],
) -> Option<AdmittedBoot> {
    entries.iter().copied().find(|entry| {
        entry.identity == identity
            && entry.kernel_version >= (6, 6, 0)
            && entry.host_os == host_os
            && entry.host_arch == host_arch
            && entry.root_profile == ROOT_PROFILE
            && entry.upper_profile == UpperProfile::SiloUpperExt4V1
            && entry.overlay_profile == OverlayProfile::SiloOverlayV1
            && entry.rendering_abi == OverlayRenderingAbi::LinuxOverlayfsMountinfoV1
            && entry.attachment_family == ATTACHMENT_FAMILY
            && entry.resolved_config_sha256 != [0; 32]
            && !entry.evidence.is_empty()
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AssetFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
}

impl AssetFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            owner: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
        }
    }

    // Unlink changes ctime but not byte identity. Callers must still authenticate
    // the retained descriptor's content; this comparison never waives its digest.
    fn unchanged_or_unlinked(self, observed: Self) -> bool {
        if observed == self {
            return true;
        }
        let after_unlink = Self {
            changed: observed.changed,
            links: observed.links,
            ..self
        };
        observed == after_unlink && observed.links < self.links
    }
}

#[derive(Debug)]
pub(crate) struct QualifiedAsset {
    file: File,
    path: PathBuf,
    fingerprint: AssetFingerprint,
    digest: [u8; 32],
}

impl QualifiedAsset {
    pub(crate) fn open(path: &Path) -> Result<Self, OverlayBootQualificationError> {
        let read_error = |source| OverlayBootQualificationError::Read {
            path: path.to_path_buf(),
            source,
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits())
            .open(path)
            .map_err(read_error)?;
        Self::from_open_file(file, path)
    }

    pub(crate) fn from_open_file(
        mut file: File,
        path: &Path,
    ) -> Result<Self, OverlayBootQualificationError> {
        let read_error = |source| OverlayBootQualificationError::Read {
            path: path.to_path_buf(),
            source,
        };
        if file.as_raw_fd() < 3 {
            let descriptor = fcntl(&file, FcntlArg::F_DUPFD_CLOEXEC(3))
                .map_err(|error| read_error(std::io::Error::from_raw_os_error(error as i32)))?;
            // F_DUPFD_CLOEXEC returns a new owned descriptor, distinct from file.
            file = unsafe { File::from_raw_fd(descriptor) };
        }
        let metadata = file.metadata().map_err(read_error)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(OverlayBootQualificationError::InvalidAsset {
                path: path.to_path_buf(),
            });
        }
        let fingerprint = AssetFingerprint::from_metadata(&metadata);
        let digest = copy_asset(&file, path, fingerprint, &mut std::io::sink())?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            fingerprint,
            digest,
        })
    }

    fn open_executable(path: &Path) -> Result<Self, OverlayBootQualificationError> {
        let asset = Self::open(path)?;
        if asset.fingerprint.mode & 0o111 == 0 {
            return Err(OverlayBootQualificationError::InvalidExecutable {
                path: path.to_path_buf(),
            });
        }
        Ok(asset)
    }

    fn recheck(&self) -> Result<(), OverlayBootQualificationError> {
        let metadata =
            self.file
                .metadata()
                .map_err(|source| OverlayBootQualificationError::Read {
                    path: self.path.clone(),
                    source,
                })?;
        let observed = AssetFingerprint::from_metadata(&metadata);
        if observed == self.fingerprint {
            return Ok(());
        }
        // Atomic restaging may unlink the old executable without changing its
        // retained inode's bytes. Permit only link removal/ctime changes, and
        // authenticate that retained inode again before executing it.
        if self.fingerprint.unchanged_or_unlinked(observed) {
            let digest = copy_asset(&self.file, &self.path, observed, &mut std::io::sink())?;
            if digest == self.digest {
                return Ok(());
            }
        }
        Err(OverlayBootQualificationError::AssetChanged {
            path: self.path.clone(),
        })
    }

    pub(crate) fn copy_into(
        &self,
        output: &mut impl Write,
    ) -> Result<u64, OverlayBootQualificationError> {
        let digest = copy_asset(&self.file, &self.path, self.fingerprint, output)?;
        if digest != self.digest {
            return Err(OverlayBootQualificationError::AssetChanged {
                path: self.path.clone(),
            });
        }
        Ok(self.fingerprint.length)
    }

    pub(crate) fn length(&self) -> u64 {
        self.fingerprint.length
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn into_source(self) -> (File, PathBuf) {
        (self.file, self.path)
    }
}

fn copy_asset(
    file: &File,
    path: &Path,
    expected: AssetFingerprint,
    output: &mut impl Write,
) -> Result<[u8; 32], OverlayBootQualificationError> {
    let read_error = |source| OverlayBootQualificationError::Read {
        path: path.to_path_buf(),
        source,
    };
    let changed = || OverlayBootQualificationError::AssetChanged {
        path: path.to_path_buf(),
    };
    let observed = AssetFingerprint::from_metadata(&file.metadata().map_err(read_error)?);
    if !expected.unchanged_or_unlinked(observed) {
        return Err(changed());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    let mut offset = 0;
    // The initial fstat length is the hard read bound. A concurrent append can
    // never extend this loop, and truncation fails instead of accepting a prefix.
    while offset < expected.length {
        let requested = (expected.length - offset).min(buffer.len() as u64) as usize;
        let count = match file.read_at(&mut buffer[..requested], offset) {
            Ok(0) => return Err(changed()),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(read_error(error)),
        };
        output.write_all(&buffer[..count]).map_err(|source| {
            OverlayBootQualificationError::Write {
                path: path.to_path_buf(),
                source,
            }
        })?;
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    let after_copy = AssetFingerprint::from_metadata(&file.metadata().map_err(read_error)?);
    if !observed.unchanged_or_unlinked(after_copy) {
        return Err(changed());
    }
    Ok(hasher.finalize().into())
}

fn hex_digest(digest: [u8; 32]) -> String {
    use std::fmt::Write;

    let mut output = String::with_capacity(64);
    for byte in digest {
        // Writing to String cannot fail.
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use crate::boot_qualification::QualifiedOverlayBoot;
    use crate::boot_qualification::{
        admit_flat_overlay, admitted_boot, AdmittedBoot, BootIdentity,
        OverlayBootQualificationError, QualifiedAsset,
    };
    use crate::GuestArchitecture;
    use rootfs_spec::{OverlayProfile, OverlayRenderingAbi, UpperProfile};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use vm_spec::live::LiveBackend;

    fn entry() -> AdmittedBoot {
        AdmittedBoot {
            identity: BootIdentity {
                kernel_sha256: [1; 32],
                initramfs_sha256: [2; 32],
                native_sha256: [4; 32],
                architecture: GuestArchitecture::Amd64,
            },
            resolved_config_sha256: [3; 32],
            kernel_version: (6, 6, 0),
            host_os: "linux",
            host_arch: "x86_64",
            root_profile: "linux-flat-overlay-v1",
            upper_profile: UpperProfile::SiloUpperExt4V1,
            overlay_profile: OverlayProfile::SiloOverlayV1,
            rendering_abi: OverlayRenderingAbi::LinuxOverlayfsMountinfoV1,
            attachment_family: "krun-virtio-blk-v1",
            evidence: "unit-only immutable tuple matching fixture",
        }
    }

    #[test]
    fn overlay_boot_qualification_matches_exact_tuple_and_host_lane() {
        let expected = entry();
        assert!(admitted_boot(expected.identity, "linux", "x86_64", &[expected]).is_some());
        for identity in [
            BootIdentity {
                kernel_sha256: [4; 32],
                ..expected.identity
            },
            BootIdentity {
                initramfs_sha256: [4; 32],
                ..expected.identity
            },
            BootIdentity {
                native_sha256: [5; 32],
                ..expected.identity
            },
            BootIdentity {
                architecture: GuestArchitecture::Arm64,
                ..expected.identity
            },
        ] {
            assert!(admitted_boot(identity, "linux", "x86_64", &[expected]).is_none());
        }
        assert!(admitted_boot(expected.identity, "macos", "aarch64", &[expected]).is_none());
        assert!(admitted_boot(expected.identity, "linux", "aarch64", &[expected]).is_none());
    }

    #[test]
    fn overlay_boot_qualification_rejects_old_kernel_and_incomplete_contract() {
        let expected = entry();
        for invalid in [
            AdmittedBoot {
                kernel_version: (5, 15, 219),
                ..expected
            },
            AdmittedBoot {
                kernel_version: (6, 5, 99),
                ..expected
            },
            AdmittedBoot {
                root_profile: "opaque-raw-v1",
                ..expected
            },
            AdmittedBoot {
                attachment_family: "vz",
                ..expected
            },
            AdmittedBoot {
                resolved_config_sha256: [0; 32],
                ..expected
            },
            AdmittedBoot {
                evidence: "",
                ..expected
            },
        ] {
            assert!(admitted_boot(expected.identity, "linux", "x86_64", &[invalid]).is_none());
        }
        assert!(admitted_boot(expected.identity, "linux", "x86_64", &[]).is_none());
    }

    #[test]
    fn overlay_boot_qualification_hashes_bytes_and_rejects_unknown_assets() {
        let directory = tempfile::tempdir().unwrap();
        let kernel = directory.path().join("kernel");
        let initramfs = directory.path().join("initramfs");
        std::fs::write(&kernel, b"abc").unwrap();
        std::fs::write(&initramfs, b"candidate base archive").unwrap();
        std::fs::set_permissions(&kernel, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            crate::boot_qualification::hex_digest(QualifiedAsset::open(&kernel).unwrap().digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let admission = admit_flat_overlay(
            &kernel,
            &initramfs,
            GuestArchitecture::Amd64,
            LiveBackend::Krun,
            &kernel,
        );
        if cfg!(target_os = "linux") {
            let error = admission.expect_err("candidate must not acquire qualification");
            let OverlayBootQualificationError::Unqualified { identity } = &error else {
                panic!("expected exact tuple rejection: {error}");
            };
            assert_eq!(identity.profile, "linux-flat-overlay-v1");
            assert_eq!(identity.architecture, GuestArchitecture::Amd64);
            assert_eq!(identity.native_sha256, identity.kernel_sha256);
            assert!(error.to_string().contains(&format!(
                "kernel sha256:{}, base initramfs sha256:{}, native sha256:{}",
                identity.kernel_sha256, identity.initramfs_sha256, identity.native_sha256,
            )));
        } else {
            assert!(matches!(
                admission,
                Err(OverlayBootQualificationError::UnsupportedHost { .. })
            ));
        }
        std::fs::write(&initramfs, []).unwrap();
        assert!(matches!(
            QualifiedAsset::open(&initramfs),
            Err(OverlayBootQualificationError::InvalidAsset { .. })
        ));
        assert!(matches!(
            QualifiedAsset::open(directory.path()),
            Err(OverlayBootQualificationError::InvalidAsset { .. })
        ));
        let symlink = directory.path().join("symlink");
        std::os::unix::fs::symlink(&kernel, &symlink).unwrap();
        assert!(matches!(
            QualifiedAsset::open(&symlink),
            Err(OverlayBootQualificationError::Read { .. })
        ));
    }

    #[test]
    fn overlay_boot_qualification_rejects_other_backends_before_opening_assets() {
        let missing = std::path::Path::new("/nonexistent/overlay-qualification-asset");
        for backend in [LiveBackend::Mock, LiveBackend::Vz] {
            assert!(matches!(
                admit_flat_overlay(missing, missing, GuestArchitecture::Amd64, backend, missing),
                Err(OverlayBootQualificationError::UnsupportedBackend { .. })
            ));
        }
    }

    #[test]
    fn overlay_boot_qualification_copy_detects_replacement_rewrite_and_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        std::fs::write(&path, b"original qualified bytes").unwrap();
        let asset = QualifiedAsset::open(&path).unwrap();
        let mut output = Vec::new();
        assert_eq!(asset.copy_into(&mut output).unwrap(), 24);
        assert_eq!(output, b"original qualified bytes");
        output.clear();
        assert_eq!(asset.copy_into(&mut output).unwrap(), 24);
        assert_eq!(output, b"original qualified bytes");

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"unqualified replacement").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let mut output = Vec::new();
        let copied = asset.copy_into(&mut output);
        assert!(copied.is_err() || output == b"original qualified bytes");
        assert_ne!(output, b"unqualified replacement");

        let asset = QualifiedAsset::open(&path).unwrap();
        std::fs::write(&path, b"same inode rewritten").unwrap();
        assert!(matches!(
            asset.copy_into(&mut Vec::new()),
            Err(OverlayBootQualificationError::AssetChanged { .. })
        ));
        let asset = QualifiedAsset::open(&path).unwrap();
        std::fs::write(&path, []).unwrap();
        assert!(matches!(
            asset.copy_into(&mut Vec::new()),
            Err(OverlayBootQualificationError::AssetChanged { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn overlay_boot_qualification_copies_retained_assets_after_atomic_parent_replacement() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let assets = directory.path().join("assets");
        let replacement = directory.path().join("replacement");
        std::fs::create_dir(&assets).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        let original_kernel = vec![42; 2 * 65536 + 17];
        let original_initramfs = vec![73; 65536 + 31];
        std::fs::write(assets.join("kernel"), &original_kernel).unwrap();
        std::fs::write(assets.join("base-initramfs"), &original_initramfs).unwrap();
        std::fs::write(replacement.join("kernel"), b"replacement kernel").unwrap();
        std::fs::write(replacement.join("base-initramfs"), b"replacement base").unwrap();
        let kernel = QualifiedAsset::open(&assets.join("kernel")).unwrap();
        let initramfs = QualifiedAsset::open(&assets.join("base-initramfs")).unwrap();

        let parent = std::fs::File::open(directory.path()).unwrap();
        nix::fcntl::renameat2(
            &parent,
            "assets",
            &parent,
            "replacement",
            nix::fcntl::RenameFlags::RENAME_EXCHANGE,
        )
        .unwrap();
        std::fs::remove_dir_all(&replacement).unwrap();
        assert_eq!(kernel.file.metadata().unwrap().nlink(), 0);
        assert_eq!(initramfs.file.metadata().unwrap().nlink(), 0);
        assert_eq!(
            std::fs::read(assets.join("kernel")).unwrap(),
            b"replacement kernel"
        );
        assert_eq!(
            std::fs::read(assets.join("base-initramfs")).unwrap(),
            b"replacement base"
        );

        let mut kernel_copy = Vec::new();
        assert_eq!(
            kernel.copy_into(&mut kernel_copy).unwrap(),
            original_kernel.len() as u64
        );
        assert_eq!(kernel_copy, original_kernel);
        let mut initramfs_copy = Vec::new();
        assert_eq!(
            initramfs.copy_into(&mut initramfs_copy).unwrap(),
            original_initramfs.len() as u64
        );
        assert_eq!(initramfs_copy, original_initramfs);
    }

    #[test]
    fn overlay_boot_qualification_copy_is_bounded_when_source_grows_during_copy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("base-initramfs");
        let original = vec![42; 2 * 65536 + 13];
        std::fs::write(&path, &original).unwrap();
        let asset = QualifiedAsset::open(&path).unwrap();
        // Real append I/O to the source during copying proves reads stop at the
        // captured initial length, then reject mutation rather than chase EOF.
        let mut appender = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            asset.copy_into(&mut appender),
            Err(OverlayBootQualificationError::AssetChanged { .. })
        ));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (original.len() * 2) as u64
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn overlay_boot_qualification_executes_retained_native_inode_across_atomic_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native-monitor");
        let shell = std::fs::canonicalize("/bin/sh").unwrap();
        std::fs::copy(shell, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let token = QualifiedOverlayBoot {
            admitted: entry(),
            kernel: QualifiedAsset::open(&path).unwrap(),
            initramfs: QualifiedAsset::open(&path).unwrap(),
            native: QualifiedAsset::open_executable(&path).unwrap(),
        };
        token.recheck_native_executable().unwrap();
        let fd = token.native_executable_fd();
        assert!(fd.as_raw_fd() >= 3);
        let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert!(
            nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
        );
        let descriptor_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let script = format!(
            "test ! -e /proc/self/fd/{} || exit 71; exit 23",
            fd.as_raw_fd()
        );
        assert_eq!(
            std::process::Command::new(&descriptor_path)
                .args(["-c", &script])
                .status()
                .unwrap()
                .code(),
            Some(23)
        );

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"#!/bin/sh\nexit 99\n").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        token.recheck_native_executable().unwrap();
        assert_eq!(
            std::process::Command::new(&path).status().unwrap().code(),
            Some(99)
        );
        // The retained inode was reauthenticated after unlink. Descriptor lookup
        // still executes the original ELF, and CLOEXEC closes its source FD.
        assert_eq!(
            std::process::Command::new(&descriptor_path)
                .args(["-c", &script])
                .status()
                .unwrap()
                .code(),
            Some(23)
        );
    }

    #[test]
    fn overlay_boot_qualification_native_recheck_rejects_in_place_mutation_and_nonexecutable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native");
        std::fs::write(&path, b"original native fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            QualifiedAsset::open_executable(&path),
            Err(OverlayBootQualificationError::InvalidExecutable { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let asset = QualifiedAsset::open_executable(&path).unwrap();
        std::fs::write(&path, b"changed native fixture!").unwrap();
        assert!(matches!(
            asset.recheck(),
            Err(OverlayBootQualificationError::AssetChanged { .. })
        ));
    }
}

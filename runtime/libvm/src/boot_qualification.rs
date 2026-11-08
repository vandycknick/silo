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

const ROOT_PROFILE: &str = "linux-erofs-overlay-v1";
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

// Only reviewed real monitor/worker observations admit exact tuples.
const ADMITTED_BOOTS: &[AdmittedBoot] = &[
    AdmittedBoot {
        identity: BootIdentity {
            kernel_sha256: [
                0x2c, 0xe7, 0x27, 0x11, 0x36, 0xaf, 0x45, 0x4c, 0x42, 0x78, 0x80, 0x21, 0x2f, 0x08,
                0x52, 0x71, 0xfc, 0x2f, 0xde, 0xa1, 0x3e, 0xfb, 0x59, 0x9b, 0xa8, 0x2f, 0xf6, 0xeb,
                0xe4, 0xd6, 0x2d, 0xc7,
            ],
            initramfs_sha256: [
                0xfa, 0x47, 0xab, 0xf6, 0x3a, 0xb4, 0x94, 0x6e, 0xfa, 0xaa, 0xcb, 0x4e, 0x03, 0x26,
                0xea, 0x3d, 0x1d, 0x95, 0x37, 0x95, 0x44, 0x4b, 0xa9, 0x07, 0x3d, 0xfa, 0x23, 0x40,
                0x7c, 0xe5, 0x7e, 0x3c,
            ],
            native_sha256: [
                0x08, 0x16, 0x52, 0x1b, 0xba, 0xf2, 0x34, 0x9c, 0x4a, 0xdb, 0x51, 0xe5, 0xac, 0x1e,
                0x72, 0x5a, 0xf4, 0x33, 0xc1, 0x48, 0x24, 0x69, 0xa5, 0x89, 0x5e, 0xbb, 0xfb, 0xc9,
                0xd3, 0xa4, 0x4b, 0x02,
            ],
            architecture: GuestArchitecture::Amd64,
        },
        resolved_config_sha256: [
            0xb8, 0x26, 0x47, 0x10, 0x3b, 0x73, 0xac, 0x2f, 0x7f, 0xaf, 0xc3, 0xb1, 0xbd, 0xd6,
            0xad, 0x92, 0x7b, 0xa2, 0xf1, 0xc6, 0x8e, 0x5b, 0x5f, 0x11, 0xa3, 0xe3, 0xda, 0x4b,
            0xfd, 0xf5, 0x33, 0xf4,
        ],
        kernel_version: (7, 2, 2),
        host_os: "linux",
        host_arch: "x86_64",
        root_profile: ROOT_PROFILE,
        upper_profile: UpperProfile::SiloUpperExt4V1,
        overlay_profile: OverlayProfile::SiloOverlayV1,
        rendering_abi: OverlayRenderingAbi::LinuxOverlayfsMountinfoV1,
        attachment_family: ATTACHMENT_FAMILY,
        evidence: "phase-22/overlay-candidate-qualification-second: silo-smoke-ih7vf9oo",
    },
    AdmittedBoot {
        identity: BootIdentity {
            kernel_sha256: [
                0x69, 0x09, 0x5b, 0x40, 0xe4, 0x89, 0xef, 0xd6, 0x7b, 0x60, 0xae, 0x3a, 0xae, 0x30,
                0x98, 0x45, 0x4f, 0x39, 0x51, 0x57, 0x27, 0xb1, 0x80, 0xce, 0x65, 0xeb, 0x9a, 0x3e,
                0xd0, 0xac, 0xe6, 0xba,
            ],
            initramfs_sha256: [
                0xfa, 0x47, 0xab, 0xf6, 0x3a, 0xb4, 0x94, 0x6e, 0xfa, 0xaa, 0xcb, 0x4e, 0x03, 0x26,
                0xea, 0x3d, 0x1d, 0x95, 0x37, 0x95, 0x44, 0x4b, 0xa9, 0x07, 0x3d, 0xfa, 0x23, 0x40,
                0x7c, 0xe5, 0x7e, 0x3c,
            ],
            native_sha256: [
                0x08, 0x16, 0x52, 0x1b, 0xba, 0xf2, 0x34, 0x9c, 0x4a, 0xdb, 0x51, 0xe5, 0xac, 0x1e,
                0x72, 0x5a, 0xf4, 0x33, 0xc1, 0x48, 0x24, 0x69, 0xa5, 0x89, 0x5e, 0xbb, 0xfb, 0xc9,
                0xd3, 0xa4, 0x4b, 0x02,
            ],
            architecture: GuestArchitecture::Amd64,
        },
        resolved_config_sha256: [
            0x21, 0x84, 0xec, 0xc3, 0xad, 0xae, 0x8b, 0x99, 0xfb, 0x19, 0x4b, 0x6f, 0xc8, 0xc4,
            0xf0, 0xd1, 0xd3, 0xb4, 0x0e, 0x54, 0x29, 0xa3, 0x00, 0xed, 0xcc, 0xbb, 0x54, 0xd0,
            0x27, 0x0b, 0x67, 0x8e,
        ],
        kernel_version: (6, 18, 48),
        host_os: "linux",
        host_arch: "x86_64",
        root_profile: ROOT_PROFILE,
        upper_profile: UpperProfile::SiloUpperExt4V1,
        overlay_profile: OverlayProfile::SiloOverlayV1,
        rendering_abi: OverlayRenderingAbi::LinuxOverlayfsMountinfoV1,
        attachment_family: ATTACHMENT_FAMILY,
        evidence: "phase-22/longterm-overlay-candidate-second: silo-smoke-xj57b84z",
    },
];

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
pub fn admit_erofs_overlay(
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
    admit_erofs_overlay_assets(
        QualifiedAsset::open(kernel)?,
        QualifiedAsset::open(initramfs)?,
        architecture,
        backend,
        native_executable,
    )
}

/// Qualify the already authenticated held guest assets, never their former paths.
pub(crate) fn admit_erofs_overlay_assets(
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
        file: File,
        path: &Path,
    ) -> Result<Self, OverlayBootQualificationError> {
        Self::from_open_file_observed(file, path, &mut std::io::sink())
    }

    /// `observer` receives exactly the bytes whose digest this asset records.
    fn from_open_file_observed(
        mut file: File,
        path: &Path,
        observer: &mut impl Write,
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
        let digest = copy_asset(&file, path, fingerprint, observer)?;
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

// Linux direct-boot kernel admission for raw roots. The kernel is admitted by
// its own bytes: the host's native direct-loader format and architecture from
// its boot header. The header is captured while the bytes are hashed, so
// admission never rereads a path or parses bytes other than the authenticated
// ones. Filesystem and device capabilities are not inspected; a kernel missing
// them fails at boot, not here.
//
//   hash pass ──► header prefix (≤ 4 KiB) ──► ELF/Image format + architecture

/// ELF program headers must lie in this prefix, as in every linked vmlinux.
const KERNEL_HEADER_BYTES: usize = 4096;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const ARM64_IMAGE_MAGIC: &[u8; 4] = b"ARM\x64";
/// The arm64 boot protocol header: flags at byte 24, magic at byte 56, ending
/// with the 32-bit `res5` field at byte 60.
const ARM64_IMAGE_HEADER_BYTES: usize = 64;
const ARM64_IMAGE_FLAGS_OFFSET: usize = 24;

#[derive(Debug, Error)]
#[error("kernel sha256:{kernel_sha256} is not an admissible {architecture:?} Linux direct-boot kernel: {reason}")]
pub struct DirectKernelRejected {
    pub kernel_sha256: String,
    pub architecture: GuestArchitecture,
    pub reason: DirectKernelRejection,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DirectKernelRejection {
    #[error("bytes are neither an x86-64 ELF vmlinux nor an arm64 Image")]
    UnrecognizedFormat,
    #[error("{actual} is not the native direct-boot kernel format for this host")]
    ForeignImage { actual: String },
    #[error("malformed kernel header: {detail}")]
    MalformedHeader { detail: &'static str },
}

/// A kernel asset plus the bounded header prefix observed while hashing it.
#[derive(Debug)]
pub(crate) struct InspectedKernel {
    asset: QualifiedAsset,
    header: KernelHeader,
}

impl InspectedKernel {
    pub(crate) fn from_open_file(
        file: File,
        path: &Path,
    ) -> Result<Self, OverlayBootQualificationError> {
        let mut header = KernelHeader::default();
        let asset = QualifiedAsset::from_open_file_observed(file, path, &mut header)?;
        Ok(Self { asset, header })
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.asset.digest
    }

    /// Overlay roots are admitted by their exact reviewed tuple instead.
    pub(crate) fn into_asset(self) -> QualifiedAsset {
        self.asset
    }

    pub(crate) fn admit_direct(
        self,
        architecture: GuestArchitecture,
    ) -> Result<QualifiedAsset, Box<DirectKernelRejected>> {
        match native_kernel_image(&self.header.0, self.asset.length(), architecture) {
            Ok(()) => Ok(self.asset),
            Err(reason) => Err(Box::new(DirectKernelRejected {
                kernel_sha256: hex_digest(self.asset.digest),
                architecture,
                reason,
            })),
        }
    }
}

/// The first `KERNEL_HEADER_BYTES` of the hashed stream.
#[derive(Debug, Default)]
struct KernelHeader(Vec<u8>);

impl Write for KernelHeader {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let wanted = KERNEL_HEADER_BYTES
            .saturating_sub(self.0.len())
            .min(bytes.len());
        self.0.extend_from_slice(&bytes[..wanted]);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn le_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DirectKernelRejection> {
    offset
        .checked_add(N)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|field| field.try_into().ok())
        .ok_or(DirectKernelRejection::MalformedHeader {
            detail: "truncated kernel header",
        })
}

fn native_kernel_image(
    header: &[u8],
    length: u64,
    architecture: GuestArchitecture,
) -> Result<(), DirectKernelRejection> {
    let malformed = |detail| DirectKernelRejection::MalformedHeader { detail };
    let foreign = |actual: &str| DirectKernelRejection::ForeignImage {
        actual: actual.to_owned(),
    };
    if header.starts_with(ELF_MAGIC) {
        let ident: [u8; 3] = le_bytes(header, 4)?;
        if ident != [2, 1, 1] {
            return Err(foreign("an ELF image that is not little-endian ELF64"));
        }
        match (u16::from_le_bytes(le_bytes(header, 18)?), architecture) {
            (EM_X86_64, GuestArchitecture::Amd64) => {}
            (EM_X86_64, GuestArchitecture::Arm64) => return Err(foreign("an x86-64 ELF vmlinux")),
            (EM_AARCH64, _) => return Err(foreign("an arm64 ELF vmlinux")),
            (machine, _) => {
                return Err(DirectKernelRejection::ForeignImage {
                    actual: format!("an ELF image for machine {machine}"),
                })
            }
        }
        return validate_elf_executable(header, length);
    }
    if header.get(56..60) == Some(ARM64_IMAGE_MAGIC.as_slice()) {
        if architecture != GuestArchitecture::Arm64 {
            return Err(foreign("an arm64 Image"));
        }
        if header.len() < ARM64_IMAGE_HEADER_BYTES {
            return Err(malformed("truncated arm64 Image header"));
        }
        let image_size = u64::from_le_bytes(le_bytes(header, 16)?);
        let flags = u64::from_le_bytes(le_bytes(header, ARM64_IMAGE_FLAGS_OFFSET)?);
        if flags & 1 != 0 {
            return Err(malformed("big-endian arm64 Image"));
        }
        if image_size == 0 {
            return Err(malformed(
                "arm64 Image header declares no effective image size",
            ));
        }
        if image_size < length {
            return Err(malformed(
                "arm64 Image is longer than its declared image size",
            ));
        }
        return Ok(());
    }
    Err(DirectKernelRejection::UnrecognizedFormat)
}

fn validate_elf_executable(header: &[u8], length: u64) -> Result<(), DirectKernelRejection> {
    let malformed = |detail| DirectKernelRejection::MalformedHeader { detail };
    if u16::from_le_bytes(le_bytes(header, 16)?) != 2 {
        return Err(malformed("ELF kernel is not an executable"));
    }
    if u32::from_le_bytes(le_bytes(header, 20)?) != 1 {
        return Err(malformed("unsupported ELF version"));
    }
    if u16::from_le_bytes(le_bytes(header, 52)?) != 64
        || u16::from_le_bytes(le_bytes(header, 54)?) != 56
    {
        return Err(malformed("unexpected ELF64 header or program-header size"));
    }
    let count = usize::from(u16::from_le_bytes(le_bytes(header, 56)?));
    if count == 0 {
        return Err(malformed("ELF kernel has no program headers"));
    }
    let start = usize::try_from(u64::from_le_bytes(le_bytes(header, 32)?))
        .ok()
        .filter(|start| *start >= 64)
        .ok_or_else(|| malformed("ELF program headers overlap the file header"))?;
    if start
        .checked_add(count * 56)
        .is_none_or(|end| end > header.len())
    {
        return Err(malformed(
            "ELF program headers lie outside the bounded kernel header",
        ));
    }
    let mut loads = 0;
    for entry in (0..count).map(|index| start + index * 56) {
        if u32::from_le_bytes(le_bytes(header, entry)?) != PT_LOAD {
            continue;
        }
        let offset = u64::from_le_bytes(le_bytes(header, entry + 8)?);
        let file_size = u64::from_le_bytes(le_bytes(header, entry + 32)?);
        let memory_size = u64::from_le_bytes(le_bytes(header, entry + 40)?);
        if offset.checked_add(file_size).is_none_or(|end| end > length) || file_size > memory_size {
            return Err(malformed("ELF loadable segment exceeds the kernel file"));
        }
        loads += 1;
    }
    if loads == 0 {
        return Err(malformed("ELF kernel has no loadable segment"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use crate::boot_qualification::QualifiedOverlayBoot;
    use crate::boot_qualification::{
        admit_erofs_overlay, admitted_boot, native_kernel_image, AdmittedBoot, BootIdentity,
        DirectKernelRejection, InspectedKernel, KernelHeader, OverlayBootQualificationError,
        QualifiedAsset,
    };
    use crate::GuestArchitecture;
    use rootfs_spec::{OverlayProfile, OverlayRenderingAbi, UpperProfile};
    use std::io::Write;
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use test_utils::direct_kernel as direct_kernel_fixture;
    use test_utils::direct_kernel::KernelArchitecture;
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
            root_profile: "linux-erofs-overlay-v1",
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
        let admission = admit_erofs_overlay(
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
            assert_eq!(identity.profile, "linux-erofs-overlay-v1");
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
                admit_erofs_overlay(missing, missing, GuestArchitecture::Amd64, backend, missing),
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

    const ARCHITECTURES: [(KernelArchitecture, GuestArchitecture); 2] = [
        (KernelArchitecture::Amd64, GuestArchitecture::Amd64),
        (KernelArchitecture::Arm64, GuestArchitecture::Arm64),
    ];

    fn header(bytes: &[u8]) -> KernelHeader {
        let mut header = KernelHeader::default();
        header.write_all(bytes).unwrap();
        header
    }

    fn admit(bytes: &[u8], architecture: GuestArchitecture) -> Result<(), DirectKernelRejection> {
        native_kernel_image(&header(bytes).0, bytes.len() as u64, architecture)
    }

    fn patch(bytes: &mut [u8], offset: usize, value: &[u8]) {
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    fn foreign(actual: &str) -> Result<(), DirectKernelRejection> {
        Err(DirectKernelRejection::ForeignImage {
            actual: actual.into(),
        })
    }

    fn malformed(detail: &'static str) -> Result<(), DirectKernelRejection> {
        Err(DirectKernelRejection::MalformedHeader { detail })
    }

    #[test]
    fn direct_kernel_admits_native_images_without_inspecting_capabilities() {
        for (fixture, architecture) in ARCHITECTURES {
            // Custom kernels need no embedded configuration; missing devices or
            // filesystems are discovered at boot.
            assert_eq!(
                admit(
                    &direct_kernel_fixture::kernel(fixture, "custom"),
                    architecture
                ),
                Ok(())
            );
            let large = direct_kernel_fixture::image(fixture, &vec![0x5a; 3 * 65536 + 17]);
            assert_eq!(admit(&large, architecture), Ok(()));
        }
        // The arm64 page-size flags (bits 1-2) are not a format requirement.
        let mut pages = direct_kernel_fixture::kernel(KernelArchitecture::Arm64, "pages");
        for page_size in [0u64, 1, 2, 3] {
            patch(&mut pages, 24, &(page_size << 1).to_le_bytes());
            assert_eq!(admit(&pages, GuestArchitecture::Arm64), Ok(()));
        }
    }

    #[test]
    fn direct_kernel_rejects_non_kernel_and_foreign_architecture_images() {
        for (_, architecture) in ARCHITECTURES {
            for bytes in [
                b"exact custom kernel".as_slice(),
                b"\x7fEL".as_slice(),
                [0u8; 128].as_slice(),
            ] {
                assert_eq!(
                    admit(bytes, architecture),
                    Err(DirectKernelRejection::UnrecognizedFormat)
                );
            }
        }
        let amd64 = direct_kernel_fixture::kernel(KernelArchitecture::Amd64, "foreign");
        let arm64 = direct_kernel_fixture::kernel(KernelArchitecture::Arm64, "foreign");
        assert_eq!(
            admit(&amd64, GuestArchitecture::Arm64),
            foreign("an x86-64 ELF vmlinux")
        );
        assert_eq!(
            admit(&arm64, GuestArchitecture::Amd64),
            foreign("an arm64 Image")
        );
        let mut aarch64_elf = amd64.clone();
        patch(&mut aarch64_elf, 18, &183u16.to_le_bytes());
        for (_, architecture) in ARCHITECTURES {
            assert_eq!(
                admit(&aarch64_elf, architecture),
                foreign("an arm64 ELF vmlinux")
            );
        }
        let mut other = amd64.clone();
        patch(&mut other, 18, &40u16.to_le_bytes());
        assert_eq!(
            admit(&other, GuestArchitecture::Amd64),
            foreign("an ELF image for machine 40")
        );
        for (offset, value) in [(4, 1), (5, 2), (6, 0)] {
            let mut elf32 = amd64.clone();
            elf32[offset] = value;
            assert_eq!(
                admit(&elf32, GuestArchitecture::Amd64),
                foreign("an ELF image that is not little-endian ELF64")
            );
        }
    }

    #[test]
    fn direct_kernel_rejects_malformed_native_headers() {
        let amd64 = direct_kernel_fixture::kernel(KernelArchitecture::Amd64, "header");
        let requirement = GuestArchitecture::Amd64;
        let length = amd64.len() as u64;
        let cases: [(usize, Vec<u8>, &'static str); 8] = [
            (
                16,
                1u16.to_le_bytes().to_vec(),
                "ELF kernel is not an executable",
            ),
            (20, 2u32.to_le_bytes().to_vec(), "unsupported ELF version"),
            (
                54,
                32u16.to_le_bytes().to_vec(),
                "unexpected ELF64 header or program-header size",
            ),
            (
                56,
                0u16.to_le_bytes().to_vec(),
                "ELF kernel has no program headers",
            ),
            (
                32,
                8u64.to_le_bytes().to_vec(),
                "ELF program headers overlap the file header",
            ),
            (
                32,
                4096u64.to_le_bytes().to_vec(),
                "ELF program headers lie outside the bounded kernel header",
            ),
            (
                64 + 32,
                (length + 1).to_le_bytes().to_vec(),
                "ELF loadable segment exceeds the kernel file",
            ),
            (
                64,
                4u32.to_le_bytes().to_vec(),
                "ELF kernel has no loadable segment",
            ),
        ];
        for (offset, value, detail) in cases {
            let mut bytes = amd64.clone();
            patch(&mut bytes, offset, &value);
            assert_eq!(admit(&bytes, requirement), malformed(detail), "{detail}");
        }
        let mut overflowing = amd64.clone();
        patch(&mut overflowing, 64 + 8, &u64::MAX.to_le_bytes());
        assert_eq!(
            admit(&overflowing, requirement),
            malformed("ELF loadable segment exceeds the kernel file")
        );
        let mut memory_smaller = amd64.clone();
        patch(&mut memory_smaller, 64 + 40, &1u64.to_le_bytes());
        assert_eq!(
            admit(&memory_smaller, requirement),
            malformed("ELF loadable segment exceeds the kernel file")
        );
        assert_eq!(
            admit(&amd64[..40], requirement),
            malformed("truncated kernel header")
        );

        let arm64 = direct_kernel_fixture::kernel(KernelArchitecture::Arm64, "header");
        let requirement = GuestArchitecture::Arm64;
        // Bit 0 of the flags at byte 24 selects big-endian; the reserved word
        // at byte 48 stays zero so only the real flags field can reject it.
        let mut big_endian = arm64.clone();
        patch(&mut big_endian, 24, &0b011u64.to_le_bytes());
        assert_eq!(&big_endian[48..56], &[0; 8]);
        assert_eq!(
            admit(&big_endian, requirement),
            malformed("big-endian arm64 Image")
        );
        let mut unsized_image = arm64.clone();
        patch(&mut unsized_image, 16, &0u64.to_le_bytes());
        assert_eq!(
            admit(&unsized_image, requirement),
            malformed("arm64 Image header declares no effective image size")
        );
        let mut short_size = arm64.clone();
        patch(&mut short_size, 16, &(arm64.len() as u64 - 1).to_le_bytes());
        assert_eq!(
            admit(&short_size, requirement),
            malformed("arm64 Image is longer than its declared image size")
        );
        // Every prefix of the 64-byte header is refused, including those that
        // already carry the magic and a declared size covering the prefix.
        for length in 0..64 {
            let truncated = &arm64[..length];
            let expected = if length >= 60 {
                malformed("truncated arm64 Image header")
            } else {
                Err(DirectKernelRejection::UnrecognizedFormat)
            };
            assert_eq!(admit(truncated, requirement), expected, "{length}");
        }
        assert_eq!(admit(&arm64[..64], requirement), Ok(()));
        assert_eq!(admit(&arm64, requirement), Ok(()));
    }

    #[test]
    fn kernel_header_capture_is_bounded_and_independent_of_write_boundaries() {
        for (fixture, _) in ARCHITECTURES {
            let kernel = direct_kernel_fixture::image(fixture, &vec![0x33; 2 * 4096 + 5]);
            let expected = header(&kernel).0;
            assert_eq!(expected, kernel[..4096]);
            for split in [0, 1, 63, 64, 4095, 4096, 4097, kernel.len()] {
                let mut observed = KernelHeader::default();
                observed.write_all(&kernel[..split]).unwrap();
                observed.write_all(&kernel[split..]).unwrap();
                assert_eq!(observed.0, expected, "split at {split}");
            }
            for chunk in [1, 7, 4095, 65536] {
                let mut chunked = KernelHeader::default();
                for part in kernel.chunks(chunk) {
                    chunked.write_all(part).unwrap();
                }
                assert_eq!(chunked.0, expected, "chunk {chunk}");
            }
        }
    }

    #[test]
    fn inspected_kernel_admits_the_authenticated_file_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        let (fixture, architecture) = ARCHITECTURES[0];
        let bytes = direct_kernel_fixture::kernel(fixture, "file");
        std::fs::write(&path, &bytes).unwrap();
        let kernel =
            InspectedKernel::from_open_file(std::fs::File::open(&path).unwrap(), &path).unwrap();
        let digest = kernel.digest();
        let asset = kernel.admit_direct(architecture).unwrap();
        assert_eq!(asset.digest(), digest);
        let mut copy = Vec::new();
        asset.copy_into(&mut copy).unwrap();
        assert_eq!(copy, bytes);

        std::fs::write(&path, b"exact custom kernel").unwrap();
        let rejected = InspectedKernel::from_open_file(std::fs::File::open(&path).unwrap(), &path)
            .unwrap()
            .admit_direct(architecture)
            .unwrap_err();
        assert_eq!(rejected.reason, DirectKernelRejection::UnrecognizedFormat);
        assert_eq!(
            rejected.kernel_sha256,
            crate::boot_qualification::hex_digest(sha256(b"exact custom kernel"))
        );
        assert!(rejected.to_string().contains(&rejected.kernel_sha256));
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(bytes).into()
    }
}

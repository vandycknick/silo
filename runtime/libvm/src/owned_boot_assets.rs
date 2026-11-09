//! Owned boot descriptors, immutable launch copies, and bounded kernel inspection.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use sha2::{Digest, Sha256};
use thiserror::Error;
use vm_spec::live::LiveBackend;

use crate::GuestArchitecture;

/// Owns guest assets and the monitor descriptor through launch.
#[derive(Debug)]
pub struct OwnedOverlayBoot {
    kernel: OwnedBootAsset,
    initramfs: OwnedBootAsset,
    native: OwnedBootAsset,
}

impl OwnedOverlayBoot {
    pub(crate) fn copy_initramfs(&self, output: &mut impl Write) -> Result<u64, BootAssetError> {
        self.initramfs.copy_into(output)
    }

    pub(crate) fn kernel_asset(&self) -> &OwnedBootAsset {
        &self.kernel
    }
    pub(crate) fn initramfs_asset(&self) -> &OwnedBootAsset {
        &self.initramfs
    }
    pub(crate) fn into_boot_assets(self) -> (OwnedBootAsset, OwnedBootAsset) {
        (self.kernel, self.initramfs)
    }

    /// Keep the CLOEXEC descriptor alive until spawn resolves /proc/self/fd/N.
    pub(crate) fn native_executable_fd(&self) -> BorrowedFd<'_> {
        self.native.file.as_fd()
    }

    pub(crate) fn recheck_native_executable(&self) -> Result<(), BootAssetError> {
        self.native.recheck()
    }
}

#[derive(Debug, Error)]
pub enum BootAssetError {
    #[error("failed to read boot asset {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("boot asset is not a nonempty regular file: {path}")]
    InvalidAsset { path: PathBuf },
    #[error("boot asset changed during inspection or launch: {path}")]
    AssetChanged { path: PathBuf },
    #[error("failed to copy boot asset {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("managed-overlay boot requires the krun backend, got {backend:?}")]
    UnsupportedBackend { backend: LiveBackend },
    #[error("managed-overlay descriptor launch is unsupported on host {host_os}")]
    UnsupportedHost { host_os: &'static str },
    #[error("managed-overlay native image is not executable: {path}")]
    InvalidExecutable { path: PathBuf },
    #[error("managed-overlay kernel version {version} is below the required Linux 6.6 floor")]
    KernelTooOld { version: String },
    #[error("cannot read managed-overlay kernel version from {path}: {detail}; Linux 6.6 or newer is required")]
    KernelVersion { path: PathBuf, detail: &'static str },
}

pub(crate) fn open_overlay_boot(
    kernel: &Path,
    initramfs: &Path,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<OwnedOverlayBoot, BootAssetError> {
    check_overlay_backend(backend)?;
    let kernel = InspectedKernel::from_asset(OwnedBootAsset::open(kernel)?)?;
    kernel.check_overlay_version()?;
    Ok(OwnedOverlayBoot {
        kernel: kernel.asset,
        initramfs: OwnedBootAsset::open(initramfs)?,
        native: OwnedBootAsset::open_executable(native_executable)?,
    })
}

fn check_overlay_backend(backend: LiveBackend) -> Result<(), BootAssetError> {
    if backend != LiveBackend::Krun {
        return Err(BootAssetError::UnsupportedBackend { backend });
    }
    if !cfg!(target_os = "linux") {
        return Err(BootAssetError::UnsupportedHost {
            host_os: std::env::consts::OS,
        });
    }
    Ok(())
}

pub(crate) fn open_overlay_assets(
    kernel: InspectedKernel,
    initramfs: OwnedBootAsset,
    backend: LiveBackend,
    native_executable: &Path,
) -> Result<OwnedOverlayBoot, BootAssetError> {
    check_overlay_backend(backend)?;
    kernel.check_overlay_version()?;
    Ok(OwnedOverlayBoot {
        kernel: kernel.asset,
        initramfs,
        native: OwnedBootAsset::open_executable(native_executable)?,
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

    // Retained guest descriptors remain authoritative after atomic publication.
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
pub(crate) struct OwnedBootAsset {
    file: File,
    path: PathBuf,
    fingerprint: AssetFingerprint,
}

impl OwnedBootAsset {
    pub(crate) fn open(path: &Path) -> Result<Self, BootAssetError> {
        let read_error = |source| BootAssetError::Read {
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

    pub(crate) fn from_open_file(mut file: File, path: &Path) -> Result<Self, BootAssetError> {
        let read_error = |source| BootAssetError::Read {
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
            return Err(BootAssetError::InvalidAsset {
                path: path.to_path_buf(),
            });
        }
        let fingerprint = AssetFingerprint::from_metadata(&metadata);
        Ok(Self {
            file,
            path: path.to_path_buf(),
            fingerprint,
        })
    }

    fn open_executable(path: &Path) -> Result<Self, BootAssetError> {
        let asset = Self::open(path)?;
        if asset.fingerprint.mode & 0o111 == 0 {
            return Err(BootAssetError::InvalidExecutable {
                path: path.to_path_buf(),
            });
        }
        Ok(asset)
    }

    fn recheck(&self) -> Result<(), BootAssetError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| BootAssetError::Read {
                path: self.path.clone(),
                source,
            })?;
        let observed = AssetFingerprint::from_metadata(&metadata);
        if observed == self.fingerprint {
            return Ok(());
        }
        Err(BootAssetError::AssetChanged {
            path: self.path.clone(),
        })
    }

    pub(crate) fn copy_into(&self, output: &mut impl Write) -> Result<u64, BootAssetError> {
        copy_asset(&self.file, &self.path, self.fingerprint, output)?;
        Ok(self.fingerprint.length)
    }

    pub(crate) fn length(&self) -> u64 {
        self.fingerprint.length
    }

    /// Content identity is computed only at capture/publication boundaries.
    pub(crate) fn digest(&self) -> Result<[u8; 32], BootAssetError> {
        let mut hasher = DigestWriter(Sha256::new());
        self.copy_into(&mut hasher)?;
        Ok(hasher.0.finalize().into())
    }

    /// Compare the bootstrap ABI input without constructing content identities.
    pub(crate) fn same_contents(&self, other: &Self) -> Result<bool, BootAssetError> {
        self.recheck()?;
        other.recheck()?;
        if self.fingerprint == other.fingerprint {
            return Ok(true);
        }
        if self.length() != other.length() {
            return Ok(false);
        }
        let mut left = [0; 65536];
        let mut right = [0; 65536];
        let mut offset = 0;
        let mut equal = true;
        while offset < self.length() {
            let count = (self.length() - offset).min(left.len() as u64) as usize;
            for (asset, buffer) in [(self, &mut left[..count]), (other, &mut right[..count])] {
                asset.file.read_exact_at(buffer, offset).map_err(|source| {
                    BootAssetError::Read {
                        path: asset.path.clone(),
                        source,
                    }
                })?;
            }
            if left[..count] != right[..count] {
                equal = false;
                break;
            }
            offset += count as u64;
        }
        self.recheck()?;
        other.recheck()?;
        Ok(equal)
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
) -> Result<(), BootAssetError> {
    let read_error = |source| BootAssetError::Read {
        path: path.to_path_buf(),
        source,
    };
    let changed = || BootAssetError::AssetChanged {
        path: path.to_path_buf(),
    };
    let observed = AssetFingerprint::from_metadata(&file.metadata().map_err(read_error)?);
    if !expected.unchanged_or_unlinked(observed) {
        return Err(changed());
    }
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
        output
            .write_all(&buffer[..count])
            .map_err(|source| BootAssetError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        offset += count as u64;
    }
    let after_copy = AssetFingerprint::from_metadata(&file.metadata().map_err(read_error)?);
    if !observed.unchanged_or_unlinked(after_copy) {
        return Err(changed());
    }
    Ok(())
}

struct DigestWriter(Sha256);
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const KERNEL_HEADER_BYTES: usize = 4096;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const ARM64_IMAGE_MAGIC: &[u8; 4] = b"ARM\x64";
const ARM64_IMAGE_HEADER_BYTES: usize = 64;
const ARM64_IMAGE_FLAGS_OFFSET: usize = 24;

#[derive(Debug, Error)]
#[error("kernel {path} is not an admissible {architecture:?} Linux direct-boot kernel: {reason}")]
pub struct DirectKernelRejected {
    pub path: PathBuf,
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

/// A held kernel and its bounded header, read without hashing the image.
#[derive(Debug)]
pub(crate) struct InspectedKernel {
    asset: OwnedBootAsset,
    header: KernelHeader,
}

impl InspectedKernel {
    pub(crate) fn from_open_file(file: File, path: &Path) -> Result<Self, BootAssetError> {
        Self::from_asset(OwnedBootAsset::from_open_file(file, path)?)
    }

    fn from_asset(asset: OwnedBootAsset) -> Result<Self, BootAssetError> {
        let mut bytes = vec![0; KERNEL_HEADER_BYTES.min(asset.length() as usize)];
        asset
            .file
            .read_exact_at(&mut bytes, 0)
            .map_err(|source| BootAssetError::Read {
                path: asset.path.clone(),
                source,
            })?;
        asset.recheck()?;
        Ok(Self {
            asset,
            header: KernelHeader(bytes),
        })
    }

    pub(crate) fn admit_direct(
        self,
        architecture: GuestArchitecture,
    ) -> Result<OwnedBootAsset, Box<DirectKernelRejected>> {
        match native_kernel_image(&self.header.0, self.asset.length(), architecture) {
            Ok(()) => Ok(self.asset),
            Err(reason) => Err(Box::new(DirectKernelRejected {
                path: self.asset.path,
                architecture,
                reason,
            })),
        }
    }

    pub(crate) fn check_overlay_version(&self) -> Result<(), BootAssetError> {
        let invalid = |detail| BootAssetError::KernelVersion {
            path: self.asset.path.clone(),
            detail,
        };
        let header = &self.header.0;
        let offset = if header.get(0x202..0x206) == Some(b"HdrS".as_slice()) {
            header
                .get(0x20e..0x210)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u16::from_le_bytes)
                .map(u64::from)
                .filter(|offset| *offset != 0)
                .ok_or_else(|| invalid("missing kernel version offset"))?
                + 0x200
        } else if header.starts_with(ELF_MAGIC) {
            self.elf_banner_offset()?
        } else {
            return Err(invalid("missing Linux boot protocol version header"));
        };
        let mut bytes = [0u8; 256];
        let count = self
            .asset
            .length()
            .checked_sub(offset)
            .filter(|length| *length != 0)
            .ok_or_else(|| invalid("kernel version offset exceeds the file"))?
            .min(bytes.len() as u64) as usize;
        self.read_exact(&mut bytes[..count], offset)?;
        self.asset.recheck()?;
        let bytes = bytes[..count]
            .strip_prefix(b"Linux version ")
            .unwrap_or(&bytes[..count]);
        let end = bytes
            .iter()
            .position(|byte| *byte == 0 || byte.is_ascii_whitespace())
            .ok_or_else(|| invalid("unterminated kernel version string"))?;
        let version = std::str::from_utf8(&bytes[..end])
            .map_err(|_| invalid("invalid kernel version string"))?;
        let mut parts = version.split('.');
        let major = parts.next().and_then(|part| part.parse::<u32>().ok());
        let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
        let (Some(major), Some(minor)) = (major, minor) else {
            return Err(invalid("invalid kernel version string"));
        };
        if (major, minor) < (6, 6) {
            return Err(BootAssetError::KernelTooOld {
                version: version.to_owned(),
            });
        }
        Ok(())
    }

    /// Native x86 kernels are ELF vmlinux, whose release lives in linux_banner.
    /// Read symbol metadata and that one string, never stream the kernel image.
    fn elf_banner_offset(&self) -> Result<u64, BootAssetError> {
        let invalid = || BootAssetError::KernelVersion {
            path: self.asset.path.clone(),
            detail: "missing or malformed ELF linux_banner",
        };
        let field = |bytes: &[u8], offset| {
            le_bytes(bytes, offset)
                .map(u64::from_le_bytes)
                .map_err(|_| invalid())
        };
        let header = &self.header.0;
        if header.get(4..7) != Some([2, 1, 1].as_slice()) {
            return Err(invalid());
        }
        let start = field(header, 40)?;
        let count = u16::from_le_bytes(le_bytes(header, 60).map_err(|_| invalid())?);
        let size = u16::from_le_bytes(le_bytes(header, 58).map_err(|_| invalid())?);
        if size != 64 || count == 0 {
            return Err(invalid());
        }
        let section = |index: u16| -> Result<[u8; 64], BootAssetError> {
            if index >= count {
                return Err(invalid());
            }
            let offset = start
                .checked_add(u64::from(index) * 64)
                .ok_or_else(invalid)?;
            self.read_array(offset)
        };
        for index in 0..count {
            let symbols = section(index)?;
            if u32::from_le_bytes(le_bytes(&symbols, 4).map_err(|_| invalid())?) != 2 {
                continue;
            }
            let strings_index = u32::from_le_bytes(le_bytes(&symbols, 40).map_err(|_| invalid())?);
            let strings = section(u16::try_from(strings_index).map_err(|_| invalid())?)?;
            let symbols_start = field(&symbols, 24)?;
            let symbols_length = field(&symbols, 32)?;
            let strings_start = field(&strings, 24)?;
            let strings_length = field(&strings, 32)?;
            if field(&symbols, 56)? != 24 || symbols_length % 24 != 0 {
                return Err(invalid());
            }
            let mut buffer = [0; 24 * 256];
            let mut offset = 0;
            while offset < symbols_length {
                let count = (symbols_length - offset).min(buffer.len() as u64) as usize;
                self.read_exact(
                    &mut buffer[..count],
                    symbols_start.checked_add(offset).ok_or_else(invalid)?,
                )?;
                for symbol in buffer[..count].chunks_exact(24) {
                    if symbol[4] != 0x11 {
                        continue;
                    }
                    let name = u64::from(u32::from_le_bytes(
                        le_bytes(symbol, 0).map_err(|_| invalid())?,
                    ));
                    if name.checked_add(13).is_none_or(|end| end > strings_length) {
                        continue;
                    }
                    let observed: [u8; 13] =
                        self.read_array(strings_start.checked_add(name).ok_or_else(invalid)?)?;
                    if &observed != b"linux_banner\0" {
                        continue;
                    }
                    let target = section(u16::from_le_bytes(
                        le_bytes(symbol, 6).map_err(|_| invalid())?,
                    ))?;
                    let address = field(symbol, 8)?;
                    let displacement = address
                        .checked_sub(field(&target, 16)?)
                        .ok_or_else(invalid)?;
                    if displacement >= field(&target, 32)? {
                        return Err(invalid());
                    }
                    return field(&target, 24)?
                        .checked_add(displacement)
                        .ok_or_else(invalid);
                }
                offset += count as u64;
            }
        }
        Err(invalid())
    }

    fn read_exact(&self, bytes: &mut [u8], offset: u64) -> Result<(), BootAssetError> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.asset.length())
        {
            return Err(BootAssetError::KernelVersion {
                path: self.asset.path.clone(),
                detail: "kernel metadata exceeds the file",
            });
        }
        self.asset
            .file
            .read_exact_at(bytes, offset)
            .map_err(|source| BootAssetError::Read {
                path: self.asset.path.clone(),
                source,
            })
    }

    fn read_array<const N: usize>(&self, offset: u64) -> Result<[u8; N], BootAssetError> {
        let mut bytes = [0; N];
        self.read_exact(&mut bytes, offset)?;
        Ok(bytes)
    }
}

/// The first `KERNEL_HEADER_BYTES` of the kernel image.
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
    use crate::owned_boot_assets::OwnedOverlayBoot;
    use crate::owned_boot_assets::{
        native_kernel_image, BootAssetError, DirectKernelRejection, InspectedKernel, KernelHeader,
        OwnedBootAsset,
    };
    use crate::GuestArchitecture;
    use std::io::Write;
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use test_utils::direct_kernel as direct_kernel_fixture;
    use test_utils::direct_kernel::KernelArchitecture;

    #[test]
    fn owned_boot_compares_base_bytes_without_hashing() {
        let directory = tempfile::tempdir().unwrap();
        let left = directory.path().join("left");
        let right = directory.path().join("right");
        let original = vec![42; 65536 + 17];
        std::fs::write(&left, &original).unwrap();
        std::fs::write(&right, &original).unwrap();
        let asset = OwnedBootAsset::open(&left).unwrap();
        assert!(asset.same_contents(&asset).unwrap());
        assert!(asset
            .same_contents(&OwnedBootAsset::open(&right).unwrap())
            .unwrap());
        let mut changed = original;
        changed[65536] = 43;
        std::fs::write(&right, &changed).unwrap();
        assert!(!asset
            .same_contents(&OwnedBootAsset::open(&right).unwrap())
            .unwrap());
        std::fs::write(&right, b"short").unwrap();
        assert!(!asset
            .same_contents(&OwnedBootAsset::open(&right).unwrap())
            .unwrap());
        std::fs::write(&left, b"mutated").unwrap();
        assert!(matches!(
            asset.same_contents(&OwnedBootAsset::open(&right).unwrap()),
            Err(BootAssetError::AssetChanged { .. })
        ));
    }

    #[test]
    fn owned_boot_rejects_empty_nonregular_and_symlink_sources() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asset");
        std::fs::write(&path, []).unwrap();
        assert!(matches!(
            OwnedBootAsset::open(&path),
            Err(BootAssetError::InvalidAsset { .. })
        ));
        assert!(matches!(
            OwnedBootAsset::open(directory.path()),
            Err(BootAssetError::InvalidAsset { .. })
        ));
        std::fs::write(&path, b"asset").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            OwnedBootAsset::open(&link),
            Err(BootAssetError::Read { .. })
        ));
    }

    #[test]
    fn overlay_boot_rejects_other_backends_before_opening_assets() {
        let missing = std::path::Path::new("/nonexistent/owned-overlay-asset");
        for backend in [
            vm_spec::live::LiveBackend::Mock,
            vm_spec::live::LiveBackend::Vz,
        ] {
            assert!(matches!(
                crate::owned_boot_assets::open_overlay_boot(missing, missing, backend, missing),
                Err(BootAssetError::UnsupportedBackend { .. })
            ));
        }
    }
    #[test]
    fn owned_boot_copy_detects_replacement_rewrite_and_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        std::fs::write(&path, b"original qualified bytes").unwrap();
        let asset = OwnedBootAsset::open(&path).unwrap();
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

        let asset = OwnedBootAsset::open(&path).unwrap();
        std::fs::write(&path, b"same inode rewritten").unwrap();
        assert!(matches!(
            asset.copy_into(&mut Vec::new()),
            Err(BootAssetError::AssetChanged { .. })
        ));
        let asset = OwnedBootAsset::open(&path).unwrap();
        std::fs::write(&path, []).unwrap();
        assert!(matches!(
            asset.copy_into(&mut Vec::new()),
            Err(BootAssetError::AssetChanged { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_boot_copies_retained_assets_after_atomic_parent_replacement() {
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
        let kernel = OwnedBootAsset::open(&assets.join("kernel")).unwrap();
        let initramfs = OwnedBootAsset::open(&assets.join("base-initramfs")).unwrap();

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
    fn owned_boot_copy_is_bounded_when_source_grows_during_copy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("base-initramfs");
        let original = vec![42; 2 * 65536 + 13];
        std::fs::write(&path, &original).unwrap();
        let asset = OwnedBootAsset::open(&path).unwrap();
        // Real append I/O to the source during copying proves reads stop at the
        // captured initial length, then reject mutation rather than chase EOF.
        let mut appender = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            asset.copy_into(&mut appender),
            Err(BootAssetError::AssetChanged { .. })
        ));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (original.len() * 2) as u64
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_boot_native_preexec_recheck_fails_closed_on_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native-monitor");
        let shell = std::fs::canonicalize("/bin/sh").unwrap();
        std::fs::copy(shell, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let token = OwnedOverlayBoot {
            kernel: OwnedBootAsset::open(&path).unwrap(),
            initramfs: OwnedBootAsset::open(&path).unwrap(),
            native: OwnedBootAsset::open_executable(&path).unwrap(),
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
        assert!(matches!(
            token.recheck_native_executable(),
            Err(BootAssetError::AssetChanged { .. })
        ));
    }

    #[test]
    fn owned_boot_native_recheck_rejects_in_place_mutation_and_nonexecutable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native");
        std::fs::write(&path, b"original native fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            OwnedBootAsset::open_executable(&path),
            Err(BootAssetError::InvalidExecutable { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let asset = OwnedBootAsset::open_executable(&path).unwrap();
        std::fs::write(&path, b"changed native fixture!").unwrap();
        assert!(matches!(
            asset.recheck(),
            Err(BootAssetError::AssetChanged { .. })
        ));
    }

    #[test]
    fn overlay_kernel_floor_rejects_old_and_malformed_headers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        for version in [
            "5.15.219",
            "6.5.99",
            "6.6.0",
            "6.18.48-custom",
            "7.2.2",
            "",
            "6",
            "invalid",
        ] {
            std::fs::write(&path, direct_kernel_fixture::bzimage(version)).unwrap();
            let kernel =
                InspectedKernel::from_open_file(std::fs::File::open(&path).unwrap(), &path)
                    .unwrap();
            let result = kernel.check_overlay_version();
            match version {
                "5.15.219" | "6.5.99" => {
                    let error = result.unwrap_err();
                    assert!(matches!(error, BootAssetError::KernelTooOld { .. }));
                    assert!(error.to_string().contains(version));
                    assert!(error.to_string().contains("6.6"));
                }
                "6.6.0" | "6.18.48-custom" | "7.2.2" => result.unwrap(),
                _ => assert!(matches!(result, Err(BootAssetError::KernelVersion { .. }))),
            }
        }
        for bytes in [vec![], vec![0; 128], b"not a Linux kernel".to_vec()] {
            std::fs::write(&path, bytes).unwrap();
            assert!(
                InspectedKernel::from_open_file(std::fs::File::open(&path).unwrap(), &path)
                    .and_then(|kernel| kernel.check_overlay_version())
                    .is_err()
            );
        }
    }

    #[test]
    fn overlay_kernel_floor_reads_native_elf_linux_banner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vmlinux");
        for version in ["5.15.219", "6.6.0", "7.2.2"] {
            let mut bytes = direct_kernel_fixture::kernel(KernelArchitecture::Amd64, "native");
            let banner = bytes.len();
            bytes.extend_from_slice(format!("Linux version {version} (build)\0").as_bytes());
            let strings = bytes.len();
            bytes.extend_from_slice(b"\0linux_banner\0");
            let strings_length = bytes.len() - strings;
            let symbols = bytes.len();
            bytes.extend_from_slice(&[0; 48]);
            let symbol = symbols + 24;
            let banner_address = 0xffff_ffff_8100_0000u64 + banner as u64;
            patch(&mut bytes, symbol, &1u32.to_le_bytes());
            bytes[symbol + 4] = 0x11;
            patch(&mut bytes, symbol + 6, &1u16.to_le_bytes());
            patch(&mut bytes, symbol + 8, &banner_address.to_le_bytes());
            patch(
                &mut bytes,
                symbol + 16,
                &((strings - banner) as u64).to_le_bytes(),
            );
            let sections = bytes.len();
            bytes.resize(sections + 4 * 64, 0);
            patch(&mut bytes, 40, &(sections as u64).to_le_bytes());
            patch(&mut bytes, 58, &64u16.to_le_bytes());
            patch(&mut bytes, 60, &4u16.to_le_bytes());
            patch(&mut bytes, sections + 64 + 4, &1u32.to_le_bytes());
            patch(&mut bytes, sections + 64 + 8, &2u64.to_le_bytes());
            patch(
                &mut bytes,
                sections + 64 + 16,
                &banner_address.to_le_bytes(),
            );
            patch(
                &mut bytes,
                sections + 64 + 24,
                &(banner as u64).to_le_bytes(),
            );
            patch(
                &mut bytes,
                sections + 64 + 32,
                &((strings - banner) as u64).to_le_bytes(),
            );
            patch(&mut bytes, sections + 128 + 4, &3u32.to_le_bytes());
            patch(
                &mut bytes,
                sections + 128 + 24,
                &(strings as u64).to_le_bytes(),
            );
            patch(
                &mut bytes,
                sections + 128 + 32,
                &(strings_length as u64).to_le_bytes(),
            );
            patch(&mut bytes, sections + 192 + 4, &2u32.to_le_bytes());
            patch(
                &mut bytes,
                sections + 192 + 24,
                &(symbols as u64).to_le_bytes(),
            );
            patch(&mut bytes, sections + 192 + 32, &48u64.to_le_bytes());
            patch(&mut bytes, sections + 192 + 40, &2u32.to_le_bytes());
            patch(&mut bytes, sections + 192 + 44, &1u32.to_le_bytes());
            patch(&mut bytes, sections + 192 + 56, &24u64.to_le_bytes());
            let length = bytes.len() as u64;
            patch(&mut bytes, 64 + 32, &length.to_le_bytes());
            patch(&mut bytes, 64 + 40, &length.to_le_bytes());
            std::fs::write(&path, bytes).unwrap();
            let kernel =
                InspectedKernel::from_open_file(std::fs::File::open(&path).unwrap(), &path)
                    .unwrap();
            let result = kernel.check_overlay_version();
            if version == "5.15.219" {
                assert!(
                    matches!(result, Err(BootAssetError::KernelTooOld { .. })),
                    "version {version}: {result:?}"
                );
            } else {
                result.unwrap_or_else(|error| panic!("version {version}: {error:?}"));
            }
        }
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
    fn inspected_kernel_admits_held_file_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        let bytes = direct_kernel_fixture::kernel(KernelArchitecture::Amd64, "file");
        std::fs::write(&path, &bytes).unwrap();
        let kernel =
            InspectedKernel::from_open_file(std::fs::File::open(&path).unwrap(), &path).unwrap();
        let asset = kernel.admit_direct(GuestArchitecture::Amd64).unwrap();
        let mut copy = Vec::new();
        asset.copy_into(&mut copy).unwrap();
        assert_eq!(copy, bytes);
    }
}

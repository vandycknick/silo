//! Valid, bounded Linux direct-boot kernel images for hypervisor-free tests.
//!
//! Each image carries the real native boot header libvm admits: an x86-64 ELF
//! executable `vmlinux` or a little-endian arm64 `Image`. They are never executed.

const ELF_BODY_OFFSET: usize = 0x1000;
const ARM64_HEADER_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelArchitecture {
    Amd64,
    Arm64,
}

impl KernelArchitecture {
    /// The architecture whose kernels this host admits.
    pub fn host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Arm64
        } else {
            Self::Amd64
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Self::Amd64 => Self::Arm64,
            Self::Arm64 => Self::Amd64,
        }
    }
}

/// A native kernel image. Distinct labels produce distinct content digests.
pub fn kernel(architecture: KernelArchitecture, label: &str) -> Vec<u8> {
    image(
        architecture,
        format!("silo kernel fixture: {label}").as_bytes(),
    )
}

/// A native kernel image for the current host architecture.
pub fn host_kernel(label: &str) -> Vec<u8> {
    kernel(KernelArchitecture::host(), label)
}

/// A valid native boot header followed by `body`.
pub fn image(architecture: KernelArchitecture, body: &[u8]) -> Vec<u8> {
    match architecture {
        KernelArchitecture::Amd64 => elf_image(body),
        KernelArchitecture::Arm64 => arm64_image(body),
    }
}

fn elf_image(body: &[u8]) -> Vec<u8> {
    let length = (ELF_BODY_OFFSET + body.len()) as u64;
    let mut image = Vec::with_capacity(ELF_BODY_OFFSET + body.len());
    image.extend_from_slice(b"\x7fELF");
    // ELFCLASS64, ELFDATA2LSB, EV_CURRENT, System V ABI and padding.
    image.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    image.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    image.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&0x0100_0000u64.to_le_bytes()); // entry
    image.extend_from_slice(&64u64.to_le_bytes()); // program headers
    image.extend_from_slice(&0u64.to_le_bytes()); // no section headers
    image.extend_from_slice(&0u32.to_le_bytes());
    image.extend_from_slice(&64u16.to_le_bytes());
    image.extend_from_slice(&56u16.to_le_bytes());
    image.extend_from_slice(&1u16.to_le_bytes());
    image.extend_from_slice(&64u16.to_le_bytes());
    image.extend_from_slice(&0u16.to_le_bytes());
    image.extend_from_slice(&0u16.to_le_bytes());
    // One PT_LOAD covering the whole file, as in a linked vmlinux.
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&5u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&0xffff_ffff_8100_0000u64.to_le_bytes());
    image.extend_from_slice(&0x0100_0000u64.to_le_bytes());
    image.extend_from_slice(&length.to_le_bytes());
    image.extend_from_slice(&length.to_le_bytes());
    image.extend_from_slice(&0x0020_0000u64.to_le_bytes());
    image.resize(ELF_BODY_OFFSET, 0);
    image.extend_from_slice(body);
    image
}

fn arm64_image(body: &[u8]) -> Vec<u8> {
    let length = (ARM64_HEADER_BYTES + body.len()) as u64;
    let mut image = Vec::with_capacity(ARM64_HEADER_BYTES + body.len());
    image.extend_from_slice(&0x9100_5a4du32.to_le_bytes()); // code0
    image.extend_from_slice(&0x1400_0000u32.to_le_bytes()); // code1
    image.extend_from_slice(&0u64.to_le_bytes()); // text_offset
    image.extend_from_slice(&length.to_le_bytes()); // image_size
    image.extend_from_slice(&0b010u64.to_le_bytes()); // little-endian, 4 KiB pages
    image.extend_from_slice(&[0; 24]); // res2, res3, res4
    image.extend_from_slice(b"ARM\x64");
    image.extend_from_slice(&0u32.to_le_bytes()); // res5
    image.extend_from_slice(body);
    image
}

#[cfg(test)]
mod tests {
    use crate::direct_kernel::{image, kernel, KernelArchitecture};

    #[test]
    fn images_carry_native_headers_and_distinct_labels() {
        let amd64 = image(KernelArchitecture::Amd64, b"body");
        assert_eq!(&amd64[..4], b"\x7fELF");
        assert_eq!(&amd64[18..20], &62u16.to_le_bytes());
        assert_eq!(
            &amd64[64 + 32..64 + 40],
            &(amd64.len() as u64).to_le_bytes()
        );
        assert!(amd64.ends_with(b"body"));
        let arm64 = image(KernelArchitecture::Arm64, b"body");
        assert_eq!(&arm64[56..60], b"ARM\x64");
        assert_eq!(&arm64[16..24], &(arm64.len() as u64).to_le_bytes());
        assert!(arm64.ends_with(b"body"));
        assert_ne!(
            kernel(KernelArchitecture::Amd64, "first"),
            kernel(KernelArchitecture::Amd64, "second")
        );
    }
}

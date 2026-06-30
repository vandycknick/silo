use crate::LibVmError;

const BYTES_PER_MEBIBYTE: u64 = 1024 * 1024;
const BYTES_PER_GIBIBYTE: u64 = 1024 * BYTES_PER_MEBIBYTE;

/// Memory size requested for a machine.
///
/// `Memory` is the public API type for VM memory. The underlying VM spec stores
/// memory in whole mebibytes today, but callers should not have to model that
/// storage detail in field names or builders.
///
/// ```rust
/// use libvm::Memory;
///
/// let memory = Memory::gibibytes(8);
/// assert_eq!(memory.as_bytes(), 8 * 1024 * 1024 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Memory {
    bytes: u64,
}

impl Memory {
    /// Creates a memory size from bytes.
    pub const fn bytes(bytes: u64) -> Self {
        Self { bytes }
    }

    /// Creates a memory size from mebibytes.
    pub const fn mebibytes(mebibytes: u64) -> Self {
        Self {
            bytes: mebibytes.saturating_mul(BYTES_PER_MEBIBYTE),
        }
    }

    /// Creates a memory size from gibibytes.
    pub const fn gibibytes(gibibytes: u64) -> Self {
        Self {
            bytes: gibibytes.saturating_mul(BYTES_PER_GIBIBYTE),
        }
    }

    /// Returns the memory size in bytes.
    pub const fn as_bytes(self) -> u64 {
        self.bytes
    }

    pub(crate) fn to_vm_spec_mebibytes(self, name: &str) -> Result<u32, LibVmError> {
        if self.bytes == 0 {
            return Err(LibVmError::InvalidCreateRequest {
                name: name.to_string(),
                reason: "memory must be greater than 0".to_string(),
            });
        }

        let mebibytes = self.bytes.div_ceil(BYTES_PER_MEBIBYTE);
        u32::try_from(mebibytes).map_err(|_| LibVmError::InvalidCreateRequest {
            name: name.to_string(),
            reason: format!("memory is too large: {} bytes", self.bytes),
        })
    }

    pub(crate) fn to_update_mebibytes(self, reference: &str) -> Result<u32, LibVmError> {
        if self.bytes == 0 {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: reference.to_string(),
                reason: "memory must be greater than 0".to_string(),
            });
        }

        let mebibytes = self.bytes.div_ceil(BYTES_PER_MEBIBYTE);
        u32::try_from(mebibytes).map_err(|_| LibVmError::InvalidMachineUpdate {
            reference: reference.to_string(),
            reason: format!("memory is too large: {} bytes", self.bytes),
        })
    }
}

use crate::changeset::{ChangesetError, ChangesetResult};

pub const MAX_UID: u64 = u32::MAX as u64 - 1;
pub const MAX_MTIME_SECONDS: u64 = 15_032_385_535;
pub const PACK_ALIGNMENT: u64 = 4096;
pub const MAX_ROOT_BYTES: u64 = 65536;
pub const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
pub const FORMAT_LIMITS: ChangesetLimits = ChangesetLimits {
    max_entries: 1_000_000,
    max_namespace_entries: 4_000_000,
    max_layers: 1024,
    max_path_bytes: 4096,
    max_component_bytes: 255,
    max_depth: 256,
    max_file_bytes: 128 * 1024 * 1024 * 1024,
    max_expanded_bytes: 1024 * 1024 * 1024 * 1024,
    // Extensions are framed inside the expanded stream. Each nonempty sparse
    // range occupies at least one logical byte, with one optional EOF sentinel.
    max_pack_bytes: 1024 * 1024 * 1024 * 1024,
    max_extension_bytes: 1024 * 1024 * 1024 * 1024,
    max_sparse_ranges: 128 * 1024 * 1024 * 1024 + 1,
    max_hardlinks: 64_999,
    max_xattrs: 64,
    max_xattr_bytes: 3072,
    max_page_entries: 4096,
    max_page_bytes: 4 * 1024 * 1024,
    max_symlink_hops: 40,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangesetLimits {
    pub max_entries: u64,
    pub max_namespace_entries: u64,
    pub max_layers: u64,
    pub max_path_bytes: u64,
    pub max_component_bytes: u64,
    pub max_depth: u64,
    pub max_file_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_pack_bytes: u64,
    pub max_extension_bytes: u64,
    pub max_sparse_ranges: u64,
    pub max_hardlinks: u64,
    pub max_xattrs: u64,
    pub max_xattr_bytes: u64,
    pub max_page_entries: u64,
    pub max_page_bytes: u64,
    pub max_symlink_hops: u64,
}
impl Default for ChangesetLimits {
    fn default() -> Self {
        FORMAT_LIMITS
    }
}
impl ChangesetLimits {
    pub fn validate(&self) -> ChangesetResult<()> {
        macro_rules! check { ($($field:ident),+)=> { $(if self.$field==0 || self.$field>FORMAT_LIMITS.$field { return Err(ChangesetError::Invalid(concat!(stringify!($field)," must be positive and may only tighten format limits").into())); })+ }; }
        check!(
            max_entries,
            max_namespace_entries,
            max_layers,
            max_path_bytes,
            max_component_bytes,
            max_depth,
            max_file_bytes,
            max_expanded_bytes,
            max_pack_bytes,
            max_extension_bytes,
            max_sparse_ranges,
            max_hardlinks,
            max_xattrs,
            max_xattr_bytes,
            max_page_entries,
            max_page_bytes,
            max_symlink_hops
        );
        Ok(())
    }
}
pub(crate) fn bounded(resource: &'static str, actual: u64, maximum: u64) -> ChangesetResult<()> {
    if actual > maximum {
        return Err(ChangesetError::Limit {
            resource,
            actual,
            maximum,
        });
    }
    Ok(())
}
pub(crate) fn aligned(length: u64) -> ChangesetResult<u64> {
    length
        .checked_add(PACK_ALIGNMENT - 1)
        .map(|v| v / PACK_ALIGNMENT * PACK_ALIGNMENT)
        .ok_or_else(|| ChangesetError::Invalid("pack alignment overflow".into()))
}

/// Host admission, not a format cap. Geometric reservations keep streaming
/// maps linear. Linux's allocator overcommits, so check currently free pages
/// before admitting each new region; allocator refusal remains a typed error.
pub(crate) fn reserve_vec<T>(values: &mut Vec<T>, additional: usize) -> ChangesetResult<()> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| ChangesetError::Allocation("allocation size overflow".into()))?;
    if required <= values.capacity() {
        return Ok(());
    }
    let capacity = required.max(values.capacity().saturating_mul(2)).max(8);
    let bytes = capacity
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(|| ChangesetError::Allocation("allocation byte size overflow".into()))?;
    memory_preflight(bytes as u64)?;
    values
        .try_reserve_exact(capacity - values.len())
        .map_err(|error| ChangesetError::Allocation(error.to_string()))
}

/// Check observed host memory separately from fallible allocation and format
/// admission, for metadata containers other than vectors as well.
pub(crate) fn memory_preflight(required: u64) -> ChangesetResult<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::{sysconf, SysconfVar};
        let pages = sysconf(SysconfVar::_AVPHYS_PAGES)
            .map_err(std::io::Error::from)?
            .ok_or_else(|| {
                ChangesetError::Allocation("available physical page count unavailable".into())
            })?;
        let page_size = sysconf(SysconfVar::PAGE_SIZE)
            .map_err(std::io::Error::from)?
            .ok_or_else(|| ChangesetError::Allocation("physical page size unavailable".into()))?;
        let available = u64::try_from(pages)
            .ok()
            .and_then(|p| u64::try_from(page_size).ok().and_then(|s| p.checked_mul(s)))
            .ok_or_else(|| {
                ChangesetError::Allocation("invalid available memory observation".into())
            })?;
        if required > available {
            return Err(ChangesetError::Resource {
                required,
                available,
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = required;
    Ok(())
}

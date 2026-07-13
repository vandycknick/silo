//! Shared ext4 block-group layout calculations.

pub(crate) fn group_count(blocks: u64, first_data_block: u32, blocks_per_group: u32) -> u32 {
    let data_blocks = blocks.saturating_sub(first_data_block as u64);
    data_blocks.div_ceil(blocks_per_group as u64) as u32
}

pub(crate) fn descriptor_blocks(groups: u32, block_size: u32, descriptor_size: u32) -> u32 {
    let descriptors_per_block = block_size / descriptor_size;
    groups.div_ceil(descriptors_per_block)
}

pub(crate) fn has_sparse_super(group: u32) -> bool {
    group == 0
        || group == 1
        || is_power_of(group, 3)
        || is_power_of(group, 5)
        || is_power_of(group, 7)
}

fn is_power_of(mut value: u32, base: u32) -> bool {
    if value < base {
        return false;
    }
    while value % base == 0 {
        value /= base;
    }
    value == 1
}

#[cfg(test)]
mod tests {
    use crate::layout::{descriptor_blocks, group_count, has_sparse_super};

    #[test]
    fn classic_sparse_super_groups_match_linux() {
        let groups: Vec<u32> = (0..100).filter(|group| has_sparse_super(*group)).collect();
        assert_eq!(groups, vec![0, 1, 3, 5, 7, 9, 25, 27, 49, 81]);
    }

    #[test]
    fn geometry_rounds_up() {
        assert_eq!(group_count(32_768, 0, 32_768), 1);
        assert_eq!(group_count(32_769, 0, 32_768), 2);
        assert_eq!(descriptor_blocks(128, 4096, 32), 1);
        assert_eq!(descriptor_blocks(129, 4096, 32), 2);
    }
}

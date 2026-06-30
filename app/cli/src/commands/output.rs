use utils::format_storage_size;

const MIB_PER_GIB: u32 = 1024;

pub(crate) fn human_bytes(size: Option<u64>) -> String {
    let Some(size) = size else {
        return "-".to_string();
    };

    format_storage_size(size)
}

pub(crate) fn human_memory_mib(memory_mib: Option<u32>) -> String {
    let Some(memory_mib) = memory_mib else {
        return "-".to_string();
    };

    if memory_mib >= MIB_PER_GIB && memory_mib % MIB_PER_GIB == 0 {
        return format!("{}G", memory_mib / MIB_PER_GIB);
    }

    format!("{memory_mib}M")
}

#[cfg(test)]
mod tests {
    use super::{human_bytes, human_memory_mib};

    #[test]
    fn formats_bytes_with_clean_units() {
        assert_eq!(human_bytes(None), "-");
        assert_eq!(human_bytes(Some(64 * 1024 * 1024 * 1024)), "64GiB");
        assert_eq!(human_bytes(Some(2 * 1024 * 1024 * 1024)), "2GiB");
        assert_eq!(human_bytes(Some(512 * 1024 * 1024)), "512MiB");
        assert_eq!(human_bytes(Some(123)), "123B");
    }

    #[test]
    fn formats_memory_from_mib() {
        assert_eq!(human_memory_mib(None), "-");
        assert_eq!(human_memory_mib(Some(512)), "512M");
        assert_eq!(human_memory_mib(Some(4096)), "4G");
    }
}

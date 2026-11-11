use crate::lobby::failure::{Code, Failure, Outcome};

const SUFFIXES: [(&str, u64); 9] = [
    ("TiB", 1 << 40),
    ("TB", 1_000_000_000_000),
    ("GiB", 1 << 30),
    ("GB", 1_000_000_000),
    ("MiB", 1 << 20),
    ("MB", 1_000_000),
    ("KiB", 1 << 10),
    ("KB", 1000),
    ("B", 1),
];

pub(crate) fn bytes(value: &str) -> Outcome<u64> {
    let (digits, scale) = SUFFIXES
        .iter()
        .find_map(|(suffix, scale)| value.strip_suffix(*suffix).map(|digits| (digits, *scale)))
        .unwrap_or((value, 1));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::new(Code::Usage, "invalid integer byte size"));
    }
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .ok_or_else(|| Failure::new(Code::Usage, "byte size overflow"))
}

/// CLI resource sizes use native binary-unit rules, unlike quota byte counts.
pub(crate) fn memory(value: &str) -> Outcome<u64> {
    libvm::planning::parse_machine_memory(value)
        .map_err(|_| Failure::new(Code::Usage, "invalid memory size"))
}

pub(crate) fn disk(value: &str) -> Outcome<u64> {
    libvm::planning::parse_root_disk_size(value)
        .map_err(|_| Failure::new(Code::Usage, "invalid root disk size"))
}

#[cfg(test)]
mod tests {
    use crate::lobby::units::{bytes, disk, memory};

    #[test]
    fn exact_sizes() {
        for (text, value) in [
            ("4GiB", 4 << 30),
            ("32MiB", 32 << 20),
            ("100GB", 100_000_000_000),
            ("0", 0),
            ("17B", 17),
        ] {
            assert_eq!(bytes(text).unwrap(), value);
        }
        for text in [
            "",
            "-1",
            "1.5GiB",
            "8garbage",
            "18446744073709551615TiB",
            " 8GiB",
        ] {
            assert!(bytes(text).is_err(), "{text}");
        }
    }

    #[test]
    fn native_resource_sizes_remain_distinct_from_quota_sizes() {
        for value in ["8gb", "8GB", "8g", "8GiB", " \t8 \n GiB \t"] {
            assert_eq!(memory(value).unwrap(), 8 << 30);
            assert_eq!(disk(value).unwrap(), 8 << 30);
        }
        assert_eq!(bytes("8GB").unwrap(), 8_000_000_000);
        for value in [
            "",
            "0g",
            "0mb",
            "1.5gb",
            "-8gb",
            "+8gb",
            "8",
            "8tb",
            "8 g b",
            "18446744073709551616m",
            "18446744073709551615g",
        ] {
            assert!(memory(value).is_err(), "{value}");
            assert!(disk(value).is_err(), "{value}");
        }
        assert!(memory("4294967296m").is_err());
        assert!(disk("17592186044416m").is_err());
    }
}

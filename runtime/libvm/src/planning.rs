//! Stateless creation planning, without opening a runtime or persistent state.

use utils::HumanSize;

use crate::LibVmError;

/// Parses CLI memory units into exact bytes, subject to the VM's u32 MiB limit.
pub fn parse_machine_memory(input: &str) -> Result<u64, String> {
    let size = input.parse::<HumanSize>()?;
    Ok(u64::from(size.memory_mib()?) << 20)
}

/// Parses CLI binary storage units into nonzero root disk bytes.
pub fn parse_root_disk_size(input: &str) -> Result<u64, String> {
    let bytes = input.parse::<HumanSize>()?.storage_bytes()?;
    if bytes == 0 {
        return Err("root disk size must be greater than 0".to_string());
    }
    Ok(bytes)
}

/// Proposes an adjective-noun-fourhex name using Silo's existing generator.
/// This neither checks availability nor reserves the name.
pub fn propose_machine_name() -> Result<String, LibVmError> {
    crate::machine::generate_machine_name()
}

#[cfg(test)]
mod tests {
    use crate::planning::{parse_machine_memory, parse_root_disk_size, propose_machine_name};

    #[test]
    fn cli_size_vectors_and_limits() {
        for (input, bytes) in [
            ("8gb", 8 << 30),
            ("8GB", 8 << 30),
            ("8g", 8 << 30),
            ("8GiB", 8 << 30),
            (" \t8 \n GiB \t", 8 << 30),
            ("512mb", 512 << 20),
            ("512M", 512 << 20),
            ("512MiB", 512 << 20),
            ("4294967295m", u64::from(u32::MAX) << 20),
        ] {
            assert_eq!(parse_machine_memory(input).unwrap(), bytes, "{input}");
            assert_eq!(parse_root_disk_size(input).unwrap(), bytes, "{input}");
        }
        for input in [
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
            assert!(parse_machine_memory(input).is_err(), "{input}");
            assert!(parse_root_disk_size(input).is_err(), "{input}");
        }
        assert!(parse_machine_memory("4294967296m").is_err());
        assert!(parse_machine_memory("4194304g").is_err());
        assert_eq!(parse_machine_memory("4194303g").unwrap(), 4194303 << 30);
        assert_eq!(
            parse_root_disk_size("17592186044415m").unwrap(),
            !((1_u64 << 20) - 1)
        );
        assert!(parse_root_disk_size("17592186044416m").is_err());
        assert_eq!(
            parse_root_disk_size("17179869183g").unwrap(),
            17179869183 << 30
        );
        assert!(parse_root_disk_size("17179869184g").is_err());
    }

    #[test]
    fn proposals_use_real_generator_without_runtime() {
        let mut names = std::collections::HashSet::new();
        for _ in 0..128 {
            let name = propose_machine_name().unwrap();
            crate::machine::validate_machine_name(&name).unwrap();
            let parts: Vec<_> = name.split('-').collect();
            assert_eq!(parts.len(), 3);
            assert_eq!(parts[2].len(), 4);
            assert!(parts[2]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            names.insert(name);
        }
        assert!(names.len() > 120);
    }
}

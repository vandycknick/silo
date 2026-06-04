use std::fmt::{Display, Formatter};
use std::str::FromStr;

const BYTES_PER_MB: u64 = 1_000_000;
const BYTES_PER_GB: u64 = 1_000_000_000;
const BYTES_PER_MIB: u64 = 1024 * 1024;
const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanSize {
    quantity: u64,
    unit: HumanSizeUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HumanSizeUnit {
    Mb,
    Gb,
    Mib,
    Gib,
}

impl HumanSize {
    pub fn bytes(self) -> Result<u64, String> {
        self.quantity
            .checked_mul(self.unit.bytes_multiplier())
            .ok_or_else(|| "size is too large".to_string())
    }

    pub fn memory_mib(self) -> Result<u32, String> {
        let mib = self
            .quantity
            .checked_mul(self.unit.memory_mib_multiplier())
            .ok_or_else(|| "memory size is too large".to_string())?;
        if mib == 0 {
            return Err("memory size must be greater than 0".to_string());
        }
        u32::try_from(mib).map_err(|_| "memory size is too large".to_string())
    }
}

impl FromStr for HumanSize {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err("size is required".to_string());
        }

        let digits_len = input
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits_len == 0 {
            return Err(
                "invalid size, expected an integer followed by mb, mib, gb, or gib".to_string(),
            );
        }

        let quantity = input[..digits_len]
            .parse::<u64>()
            .map_err(|err| format!("invalid size quantity: {err}"))?;
        let unit = input[digits_len..].trim_start();
        if unit.is_empty() {
            return Err("invalid size, missing unit; use mb, mib, gb, or gib".to_string());
        }
        if !unit.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err("invalid size unit; use mb, mib, gb, or gib".to_string());
        }

        let unit = HumanSizeUnit::parse(unit)?;
        let size = Self { quantity, unit };
        let _ = size.bytes()?;
        Ok(size)
    }
}

impl Display for HumanSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.quantity, self.unit)
    }
}

impl HumanSizeUnit {
    fn parse(input: &str) -> Result<Self, String> {
        match input.to_ascii_lowercase().as_str() {
            "mb" => Ok(Self::Mb),
            "gb" => Ok(Self::Gb),
            "mib" => Ok(Self::Mib),
            "gib" => Ok(Self::Gib),
            _ => Err("invalid size unit; use mb, mib, gb, or gib".to_string()),
        }
    }

    fn bytes_multiplier(self) -> u64 {
        match self {
            Self::Mb => BYTES_PER_MB,
            Self::Gb => BYTES_PER_GB,
            Self::Mib => BYTES_PER_MIB,
            Self::Gib => BYTES_PER_GIB,
        }
    }

    fn memory_mib_multiplier(self) -> u64 {
        match self {
            Self::Mb | Self::Mib => 1,
            Self::Gb | Self::Gib => 1024,
        }
    }
}

impl Display for HumanSizeUnit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let suffix = match self {
            Self::Mb => "mb",
            Self::Gb => "gb",
            Self::Mib => "mib",
            Self::Gib => "gib",
        };
        f.write_str(suffix)
    }
}

pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn parse_mac(input: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 6 {
        return Err("expected MAC as xx:xx:xx:xx:xx:xx".to_string());
    }

    let mut mac = [0; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!(
                "invalid MAC byte {part:?}: expected two hex digits"
            ));
        }
        mac[index] = u8::from_str_radix(part, 16)
            .map_err(|err| format!("invalid MAC byte {part:?}: {err}"))?;
    }

    if mac[0] & 0x01 != 0 {
        return Err("MAC address cannot be multicast".to_string());
    }

    Ok(mac)
}

#[cfg(test)]
mod tests {
    use crate::{format_mac, parse_mac, HumanSize};

    #[test]
    fn formats_mac_as_lowercase_colon_hex() {
        assert_eq!(
            format_mac([0x02, 0x94, 0xef, 0xe4, 0x0c, 0xee]),
            "02:94:ef:e4:0c:ee"
        );
    }

    #[test]
    fn parses_colon_hex_mac() {
        assert_eq!(
            parse_mac("02:94:ef:e4:0c:ee").expect("parse mac"),
            [0x02, 0x94, 0xef, 0xe4, 0x0c, 0xee]
        );
    }

    #[test]
    fn rejects_multicast_mac() {
        assert!(parse_mac("03:94:ef:e4:0c:ee").is_err());
    }

    #[test]
    fn parses_human_size_units() {
        assert_eq!(
            "100mb".parse::<HumanSize>().expect("parse mb").bytes(),
            Ok(100_000_000)
        );
        assert_eq!(
            "1 gb".parse::<HumanSize>().expect("parse gb").bytes(),
            Ok(1_000_000_000)
        );
        assert_eq!(
            "512MiB".parse::<HumanSize>().expect("parse mib").bytes(),
            Ok(536_870_912)
        );
        assert_eq!(
            "2GiB".parse::<HumanSize>().expect("parse gib").bytes(),
            Ok(2_147_483_648)
        );
    }

    #[test]
    fn human_size_memory_uses_mib_units() {
        assert_eq!(
            "100mb"
                .parse::<HumanSize>()
                .expect("parse size")
                .memory_mib(),
            Ok(100)
        );
        assert_eq!(
            "4gb".parse::<HumanSize>().expect("parse size").memory_mib(),
            Ok(4096)
        );
        assert_eq!(
            "512mib"
                .parse::<HumanSize>()
                .expect("parse size")
                .memory_mib(),
            Ok(512)
        );
        assert_eq!(
            "1gib"
                .parse::<HumanSize>()
                .expect("parse size")
                .memory_mib(),
            Ok(1024)
        );
    }

    #[test]
    fn rejects_human_size_without_unit() {
        assert!("4096".parse::<HumanSize>().is_err());
        assert!("40".parse::<HumanSize>().is_err());
    }

    #[test]
    fn rejects_invalid_human_size_syntax() {
        for input in ["", "gb", "1.5gb", "1tb", "1 gb extra", "1g b"] {
            assert!(input.parse::<HumanSize>().is_err(), "{input:?} should fail");
        }
    }
}
